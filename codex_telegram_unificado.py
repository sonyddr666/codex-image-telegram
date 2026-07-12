#!/usr/bin/env python3
"""Bot Telegram autocontido para Codex, contas ChatGPT e imagens.

O módulo reúne autenticação, persistência, cliente HTTP e handlers do Telegram.
O token do Telegram é lido somente da variável de ambiente em main().
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import logging
import os
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, urlencode, urlsplit

import requests
from PIL import Image, UnidentifiedImageError
from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)


# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

APP_NAME = "codex-telegram-unificado"
APP_VERSION = "1.0.0"

AUTH_ISSUER = "https://auth.openai.com"
OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
OAUTH_ORIGINATOR = "codex_cli_rs"
OAUTH_TOKEN_URL = f"{AUTH_ISSUER}/oauth/token"
DEVICE_USERCODE_URL = f"{AUTH_ISSUER}/api/accounts/deviceauth/usercode"
DEVICE_TOKEN_URL = f"{AUTH_ISSUER}/api/accounts/deviceauth/token"
DEVICE_VERIFICATION_URL = f"{AUTH_ISSUER}/codex/device"
DEVICE_REDIRECT_URI = f"{AUTH_ISSUER}/deviceauth/callback"

BROWSER_AUTH_URL = f"{AUTH_ISSUER}/oauth/authorize"
BROWSER_REDIRECT_URI = "http://localhost:1455/auth/callback"
BROWSER_SCOPE = (
    "openid profile email offline_access "
    "api.connectors.read api.connectors.invoke"
)

CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
QUOTA_ENDPOINT = "https://chatgpt.com/backend-api/wham/usage"


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


DATA_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).parent)).expanduser().resolve()
IMAGES_DIR = DATA_DIR / "imagens"
REFERENCES_DIR = DATA_DIR / "referencias"

DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "gpt-5.4-mini").strip() or "gpt-5.4-mini"
IMAGE_MODEL = os.environ.get("IMAGE_MODEL", "gpt-image-2").strip() or "gpt-image-2"
MAX_IMAGES = env_int("MAX_IMAGES", 5, 1, 5)
MAX_HISTORY_MESSAGES = env_int("MAX_HISTORY_MESSAGES", 30, 2, 100)
MAX_AUTH_JSON_BYTES = env_int("MAX_AUTH_JSON_BYTES", 512 * 1024, 1024, 2 * 1024 * 1024)
MAX_CHAT_CHARS = env_int("MAX_CHAT_CHARS", 20_000, 100, 100_000)
MIN_CUSTOM_DIMENSION = env_int("MIN_CUSTOM_DIMENSION", 256, 64, 1024)
MAX_CUSTOM_DIMENSION = env_int("MAX_CUSTOM_DIMENSION", 4096, 1024, 8192)
MAX_CUSTOM_PIXELS = env_int("MAX_CUSTOM_PIXELS", 16_777_216, 1_048_576, 67_108_864)
SYSTEM_PROMPT = os.environ.get(
    "SYSTEM_PROMPT",
    "Responda em português do Brasil de forma objetiva, clara e natural.",
).strip()


def parse_allowed_user_ids(raw: str) -> frozenset[int]:
    result: set[int] = set()
    for item in re.split(r"[,;\s]+", raw.strip()):
        if not item:
            continue
        try:
            result.add(int(item))
        except ValueError:
            continue
    return frozenset(result)


ALLOWED_TELEGRAM_USER_IDS = parse_allowed_user_ids(
    os.environ.get("ALLOWED_TELEGRAM_USER_IDS", "")
)

for directory in (DATA_DIR, IMAGES_DIR, REFERENCES_DIR):
    directory.mkdir(parents=True, exist_ok=True)

Image.MAX_IMAGE_PIXELS = 40_000_000

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logger = logging.getLogger(APP_NAME)

AUTH_FILE_LOCK = threading.RLock()


# ---------------------------------------------------------------------------
# Erros e redaction
# ---------------------------------------------------------------------------


class UserVisibleError(RuntimeError):
    """Erro seguro para exibição no Telegram."""


class LoginCancelled(UserVisibleError):
    pass


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]*)?\b")
_TELEGRAM_TOKEN_RE = re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{20,}\b")
_NAMED_SECRET_RE = re.compile(
    r"(?i)((?:access|refresh|id)[_-]?token|authorization)\s*[:=]\s*['\"]?[^\s,'\"}]+"
)


def redact_secrets(value: Any) -> str:
    text = str(value)
    text = _JWT_RE.sub("<token-redacted>", text)
    text = _TELEGRAM_TOKEN_RE.sub("<telegram-token-redacted>", text)
    text = _NAMED_SECRET_RE.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    return text[:1000]


def response_error(response: requests.Response, context: str) -> UserVisibleError:
    detail = ""
    try:
        body = response.json()
    except (ValueError, requests.JSONDecodeError):
        body = None

    if isinstance(body, dict):
        candidate = body.get("error_description") or body.get("message") or body.get("detail")
        error = body.get("error")
        if isinstance(error, dict):
            candidate = candidate or error.get("message") or error.get("code")
        elif isinstance(error, str):
            candidate = candidate or error
        if candidate:
            detail = f": {redact_secrets(candidate)}"

    return UserVisibleError(f"{context}: HTTP {response.status_code}{detail}")


def safe_exception(exc: BaseException) -> str:
    if isinstance(exc, requests.Timeout):
        return "tempo limite de conexão excedido"
    if isinstance(exc, requests.ConnectionError):
        return "não foi possível conectar ao serviço"
    return redact_secrets(exc)


# ---------------------------------------------------------------------------
# JWT, tokens e arquivos de autenticação
# ---------------------------------------------------------------------------


def decode_jwt_payload(token: str | None) -> dict[str, Any]:
    if not token or not isinstance(token, str):
        return {}
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
        return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return {}


def jwt_email(token: str | None) -> str:
    claims = decode_jwt_payload(token)
    profile = claims.get("https://api.openai.com/profile")
    if isinstance(profile, dict) and isinstance(profile.get("email"), str):
        return profile["email"].strip()
    email = claims.get("email")
    return email.strip() if isinstance(email, str) else ""


def jwt_account_id(token: str | None) -> str:
    claims = decode_jwt_payload(token)
    auth = claims.get("https://api.openai.com/auth")
    if isinstance(auth, dict):
        for key in ("chatgpt_account_id", "chatgpt_account_user_id"):
            value = auth.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def jwt_plan_type(token: str | None) -> str:
    claims = decode_jwt_payload(token)
    auth = claims.get("https://api.openai.com/auth")
    if isinstance(auth, dict):
        value = auth.get("chatgpt_plan_type")
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return "personal"


def jwt_expiration(token: str | None) -> int | None:
    value = decode_jwt_payload(token).get("exp")
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def is_token_expired(token: str | None, buffer_seconds: int = 90) -> bool:
    expiration = jwt_expiration(token)
    return bool(expiration and time.time() >= expiration - buffer_seconds)


def plan_label(plan_type: str | None) -> str:
    normalized = (plan_type or "personal").strip().lower()
    labels = {
        "free": "Gratuito",
        "plus": "Plus",
        "pro": "Pro",
        "team": "Team",
        "business": "Business",
        "enterprise": "Enterprise",
        "edu": "Edu",
        "k12": "Educação (K12)",
        "personal": "Pessoal",
    }
    return labels.get(normalized, normalized or "Desconhecido")


def format_expiration(token: str | None) -> str:
    expiration = jwt_expiration(token)
    if not expiration:
        return "não informado"
    return datetime.fromtimestamp(expiration, tz=timezone.utc).astimezone().strftime("%d/%m %H:%M")


@dataclass(repr=False)
class TokenBundle:
    access_token: str
    refresh_token: str | None = None
    id_token: str | None = None
    account_id: str | None = None
    label: str | None = None

    def __post_init__(self) -> None:
        self.access_token = self.access_token.strip()
        self.refresh_token = self.refresh_token.strip() if self.refresh_token else None
        self.id_token = self.id_token.strip() if self.id_token else None
        self.account_id = (self.account_id or jwt_account_id(self.access_token) or None)
        self.label = self.label.strip() if self.label else None
        if not self.access_token or len(self.access_token) > 200_000:
            raise UserVisibleError("access_token ausente ou inválido")

    @property
    def email(self) -> str:
        return jwt_email(self.access_token) or jwt_email(self.id_token)

    @property
    def plan_type(self) -> str:
        plan = jwt_plan_type(self.access_token)
        return plan if plan != "personal" else jwt_plan_type(self.id_token)

    @property
    def identity(self) -> str:
        if self.account_id:
            return f"account:{self.account_id}"
        if self.email:
            return f"email:{self.email.lower()}:{self.plan_type}"
        digest = hashlib.sha256(self.access_token.encode("utf-8")).hexdigest()[:24]
        return f"token:{digest}"


def string_value(mapping: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def bundle_from_mapping(
    mapping: dict[str, Any],
    parent: dict[str, Any] | None = None,
    inherited_label: str | None = None,
) -> TokenBundle | None:
    parent = parent or mapping
    tokens = mapping.get("tokens") if isinstance(mapping.get("tokens"), dict) else mapping
    if not isinstance(tokens, dict):
        tokens = mapping

    access = string_value(tokens, "access_token", "access")
    if not access and tokens is not parent:
        access = string_value(parent, "access_token", "access")
    if not access:
        return None

    refresh = string_value(tokens, "refresh_token", "refresh") or string_value(
        parent, "refresh_token", "refresh"
    )
    id_token = string_value(tokens, "id_token") or string_value(parent, "id_token")
    account_id = string_value(tokens, "account_id", "accountId") or string_value(
        mapping, "account_id", "accountId"
    )
    extra = mapping.get("extra")
    if not account_id and isinstance(extra, dict):
        account_id = string_value(extra, "account_id", "accountId")
    label = string_value(mapping, "label") or string_value(parent, "label") or inherited_label

    return TokenBundle(
        access_token=access,
        refresh_token=refresh,
        id_token=id_token,
        account_id=account_id,
        label=label,
    )


def extract_token_bundles(data: Any) -> list[TokenBundle]:
    candidates: list[tuple[dict[str, Any], dict[str, Any], str | None]] = []

    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                candidates.append((item, item, None))
    elif isinstance(data, dict):
        pool_root = data.get("credential_pool")
        if isinstance(pool_root, dict):
            pool = pool_root.get("openai-codex") or pool_root.get("openai_codex")
            if isinstance(pool, list):
                for item in pool:
                    if isinstance(item, dict):
                        candidates.append((item, data, string_value(data, "label")))
            elif isinstance(pool, dict):
                candidates.append((pool, data, string_value(data, "label")))
        candidates.append((data, data, string_value(data, "label")))
    else:
        raise UserVisibleError("o JSON precisa conter um objeto ou uma lista de contas")

    bundles: list[TokenBundle] = []
    seen: set[str] = set()
    for mapping, parent, label in candidates:
        bundle = bundle_from_mapping(mapping, parent, label)
        if bundle and bundle.identity not in seen:
            bundles.append(bundle)
            seen.add(bundle.identity)

    if not bundles:
        raise UserVisibleError("não encontrei access_token em um formato de auth suportado")
    return bundles


def auth_file_sort_key(path: Path) -> tuple[int, str]:
    match = re.fullmatch(r"auth(\d*)\.json", path.name, flags=re.IGNORECASE)
    if match:
        return (int(match.group(1) or 0), path.name.lower())
    return (10**9, path.name.lower())


def discover_auth_files() -> list[Path]:
    return sorted(
        (path for path in DATA_DIR.glob("auth*.json") if path.is_file()),
        key=auth_file_sort_key,
    )


def read_auth_json(path: Path) -> Any:
    if path.stat().st_size > 2 * 1024 * 1024:
        raise UserVisibleError(f"arquivo de autenticação muito grande: {path.name}")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def next_auth_file() -> Path:
    existing = {path.name.lower() for path in discover_auth_files()}
    index = 1
    while f"auth{index}.json" in existing:
        index += 1
    return DATA_DIR / f"auth{index}.json"


def atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temp_path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def safe_label(bundle: TokenBundle) -> str:
    if bundle.label:
        value = bundle.label
    elif bundle.email:
        value = f"{bundle.email.split('@', 1)[0]}_{bundle.plan_type}"
    else:
        value = f"conta_{bundle.plan_type}"
    value = re.sub(r"[^A-Za-z0-9._@-]+", "_", value).strip("._-")
    return value[:80] or "conta_codex"


def normalized_auth_payload(bundle: TokenBundle) -> dict[str, Any]:
    return {
        "label": safe_label(bundle),
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": bundle.id_token,
            "access_token": bundle.access_token,
            "refresh_token": bundle.refresh_token,
            "account_id": bundle.account_id,
        },
        "last_refresh": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


@dataclass(frozen=True)
class SaveResult:
    label: str
    path: Path
    identity: str
    action: str


def find_matching_auth(bundle: TokenBundle) -> tuple[Path, bool, bool] | None:
    for path in discover_auth_files():
        try:
            existing = extract_token_bundles(read_auth_json(path))
        except (OSError, ValueError, UserVisibleError):
            continue
        for item in existing:
            if item.identity == bundle.identity:
                return path, len(existing) == 1, item.access_token == bundle.access_token
    return None


def save_token_bundle(bundle: TokenBundle) -> SaveResult:
    with AUTH_FILE_LOCK:
        match = find_matching_auth(bundle)
        if match:
            path, single_account_file, same_access = match
            if same_access:
                return SaveResult(safe_label(bundle), path, bundle.identity, "já existia")
            if single_account_file:
                atomic_write_json(path, normalized_auth_payload(bundle))
                return SaveResult(safe_label(bundle), path, bundle.identity, "atualizada")

        path = next_auth_file()
        atomic_write_json(path, normalized_auth_payload(bundle))
        return SaveResult(safe_label(bundle), path, bundle.identity, "importada")


def save_auth_data(data: Any) -> list[SaveResult]:
    return [save_token_bundle(bundle) for bundle in extract_token_bundles(data)]


def update_tokens_in_auth_file(
    path: Path,
    old_access_token: str,
    bundle: TokenBundle,
) -> bool:
    with AUTH_FILE_LOCK:
        try:
            data = read_auth_json(path)
        except (OSError, ValueError, UserVisibleError):
            return False

        changed = False

        def visit(value: Any) -> None:
            nonlocal changed
            if isinstance(value, dict):
                access_key = None
                for key in ("access_token", "access"):
                    if value.get(key) == old_access_token:
                        access_key = key
                        break
                if access_key:
                    value[access_key] = bundle.access_token
                    refresh_key = "refresh_token" if access_key == "access_token" else "refresh"
                    if bundle.refresh_token:
                        value[refresh_key] = bundle.refresh_token
                    if bundle.id_token:
                        value["id_token"] = bundle.id_token
                    if bundle.account_id:
                        value["account_id"] = bundle.account_id
                    changed = True
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(data)
        if changed:
            if isinstance(data, dict):
                data["last_refresh"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            atomic_write_json(path, data)
        return changed


def renew_tokens(refresh_token: str) -> TokenBundle:
    try:
        response = requests.post(
            OAUTH_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "client_id": OAUTH_CLIENT_ID,
                "refresh_token": refresh_token,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=(10, 30),
        )
    except requests.RequestException as exc:
        raise UserVisibleError(f"falha ao renovar a sessão: {safe_exception(exc)}") from exc

    if not response.ok:
        raise response_error(response, "falha ao renovar a sessão")
    try:
        body = response.json()
    except ValueError as exc:
        raise UserVisibleError("a renovação retornou uma resposta inválida") from exc
    bundle = bundle_from_mapping(body)
    if not bundle:
        raise UserVisibleError("a renovação não retornou access_token")
    if not bundle.refresh_token:
        bundle.refresh_token = refresh_token
    return bundle


# ---------------------------------------------------------------------------
# Contas, quota e cliente Codex
# ---------------------------------------------------------------------------


def to_epoch_seconds(value: Any) -> float | None:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number / 1000.0 if number > 1_000_000_000_000 else number


def format_remaining(timestamp: float | None) -> str:
    if timestamp is None:
        return "não informado"
    seconds = int(timestamp - time.time())
    if seconds <= 0:
        return "agora"
    days, seconds = divmod(seconds, 86_400)
    hours, seconds = divmod(seconds, 3_600)
    minutes = seconds // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m"


def walk_dicts(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], dict[str, Any]]]:
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            yield from walk_dicts(child, path + (str(key).lower(),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_dicts(child, path + (str(index),))


def parse_quota(body: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "plan": body.get("plan_type") or body.get("planType") or "-",
    }
    windows: list[dict[str, Any]] = []

    for path, node in walk_dicts(body):
        used = node.get("used_percent", node.get("usedPercent"))
        left = node.get("percent_left", node.get("percentLeft"))
        try:
            if left is not None:
                remaining = float(left)
            elif used is not None:
                remaining = 100.0 - float(used)
            else:
                continue
        except (TypeError, ValueError):
            continue

        reset = (
            node.get("reset_at")
            or node.get("resetsAt")
            or node.get("reset_time_ms")
        )
        if reset is None and node.get("reset_after_seconds") is not None:
            try:
                reset = time.time() + float(node["reset_after_seconds"])
            except (TypeError, ValueError):
                reset = None

        duration_seconds: float | None = None
        duration = node.get("limit_window_seconds")
        if duration is not None:
            try:
                duration_seconds = float(duration)
            except (TypeError, ValueError):
                pass
        if duration_seconds is None and node.get("windowDurationMins") is not None:
            try:
                duration_seconds = float(node["windowDurationMins"]) * 60
            except (TypeError, ValueError):
                pass

        windows.append(
            {
                "remaining": max(0.0, min(100.0, remaining)),
                "reset": to_epoch_seconds(reset),
                "duration": duration_seconds,
                "path": ".".join(path),
            }
        )

    def pick(names: tuple[str, ...], long_window: bool) -> dict[str, Any] | None:
        named = [item for item in windows if any(name in item["path"] for name in names)]
        if named:
            return named[0]
        with_duration = [item for item in windows if item["duration"] is not None]
        if not with_duration:
            return None
        return max(with_duration, key=lambda item: item["duration"]) if long_window else min(
            with_duration, key=lambda item: item["duration"]
        )

    five_hour = pick(("primary_window", "primary"), long_window=False)
    weekly = pick(("secondary_window", "secondary", "weekly"), long_window=True)
    if five_hour is None and windows:
        five_hour = windows[0]
    if weekly is None and len(windows) > 1:
        weekly = windows[1]

    if five_hour:
        result["five_hour_pct"] = five_hour["remaining"]
        result["five_hour_reset"] = five_hour["reset"]
    if weekly and weekly is not five_hour:
        result["weekly_pct"] = weekly["remaining"]
        result["weekly_reset"] = weekly["reset"]
    return result


class CodexAccount:
    def __init__(self, bundle: TokenBundle, auth_file: Path, label: str | None = None):
        self.access_token = bundle.access_token
        self.refresh_token = bundle.refresh_token
        self.id_token = bundle.id_token
        self.account_id = bundle.account_id or jwt_account_id(bundle.access_token) or None
        self.auth_file = auth_file
        self.label = label or bundle.label or auth_file.stem
        self._refresh_lock = threading.Lock()
        self._refresh_properties()

    def _refresh_properties(self) -> None:
        self.email = jwt_email(self.access_token) or jwt_email(self.id_token) or "não informado"
        self.plan_type = jwt_plan_type(self.access_token)
        if self.plan_type == "personal" and self.id_token:
            self.plan_type = jwt_plan_type(self.id_token)
        self.expires_at = jwt_expiration(self.access_token)

    @property
    def identity(self) -> str:
        return TokenBundle(
            access_token=self.access_token,
            refresh_token=self.refresh_token,
            id_token=self.id_token,
            account_id=self.account_id,
        ).identity

    @property
    def headers(self) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://chatgpt.com",
            "Referer": "https://chatgpt.com/",
            "User-Agent": f"{APP_NAME}/{APP_VERSION}",
            "originator": OAUTH_ORIGINATOR,
        }
        if self.account_id:
            headers["ChatGPT-Account-ID"] = self.account_id
        return headers

    def refresh(self, force: bool = False) -> bool:
        with self._refresh_lock:
            if not force and not is_token_expired(self.access_token):
                return True
            if not self.refresh_token:
                return False
            old_access = self.access_token
            try:
                bundle = renew_tokens(self.refresh_token)
            except UserVisibleError as exc:
                logger.warning("Falha ao renovar %s: %s", self.label, safe_exception(exc))
                return False
            self.access_token = bundle.access_token
            self.refresh_token = bundle.refresh_token or self.refresh_token
            self.id_token = bundle.id_token or self.id_token
            self.account_id = bundle.account_id or self.account_id
            self._refresh_properties()
            update_tokens_in_auth_file(
                self.auth_file,
                old_access,
                TokenBundle(
                    access_token=self.access_token,
                    refresh_token=self.refresh_token,
                    id_token=self.id_token,
                    account_id=self.account_id,
                    label=self.label,
                ),
            )
            return True

    def ensure_valid(self) -> None:
        if is_token_expired(self.access_token) and not self.refresh(force=True):
            raise UserVisibleError("a sessão da conta expirou; faça login ou importe auth.json novamente")

    def check_quota(self) -> dict[str, Any]:
        for attempt in range(2):
            self.ensure_valid()
            try:
                response = requests.get(
                    QUOTA_ENDPOINT,
                    headers=self.headers,
                    timeout=(10, 30),
                )
            except requests.RequestException as exc:
                return {"error": safe_exception(exc)}
            if response.status_code == 401 and attempt == 0 and self.refresh(force=True):
                continue
            if response.ok:
                try:
                    body = response.json()
                except ValueError:
                    return {"error": "resposta de quota inválida"}
                return parse_quota(body) if isinstance(body, dict) else {"error": "resposta de quota inválida"}
            return {"error": str(response_error(response, "falha ao consultar quota"))}
        return {"error": "não foi possível autenticar a conta"}


class AuthManager:
    def load_accounts(self) -> list[CodexAccount]:
        accounts: list[CodexAccount] = []
        for auth_file in discover_auth_files():
            try:
                data = read_auth_json(auth_file)
                bundles = extract_token_bundles(data)
            except (OSError, ValueError, UserVisibleError) as exc:
                logger.warning("Ignorando %s: %s", auth_file.name, safe_exception(exc))
                continue
            for index, bundle in enumerate(bundles, start=1):
                label = bundle.label or auth_file.stem
                if len(bundles) > 1:
                    label = f"{label} #{index}"
                accounts.append(CodexAccount(bundle, auth_file, label))
        return accounts

    def find(self, identity: str | None) -> CodexAccount | None:
        if not identity:
            return None
        return next((account for account in self.load_accounts() if account.identity == identity), None)


def extract_response_text(value: Any) -> str:
    parts: list[str] = []
    if isinstance(value, dict):
        if isinstance(value.get("text"), str):
            parts.append(value["text"])
        for key in ("output", "content", "response"):
            if key in value:
                nested = extract_response_text(value[key])
                if nested:
                    parts.append(nested)
    elif isinstance(value, list):
        for item in value:
            nested = extract_response_text(item)
            if nested:
                parts.append(nested)
    return "".join(parts)


class CodexClient:
    def __init__(self, account: CodexAccount, base_url: str = CODEX_BASE_URL):
        self.account = account
        self.base_url = base_url.rstrip("/")

    def headers(self, streaming: bool = False) -> dict[str, str]:
        headers = self.account.headers.copy()
        headers["Accept"] = "text/event-stream" if streaming else "application/json"
        return headers

    @staticmethod
    def build_input(history: list[dict[str, str]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for message in history[-MAX_HISTORY_MESSAGES:]:
            text = str(message.get("content", "")).strip()
            if not text:
                continue
            role = "assistant" if message.get("role") == "assistant" else "user"
            result.append(
                {
                    "type": "message",
                    "role": role,
                    "content": [
                        {
                            "type": "output_text" if role == "assistant" else "input_text",
                            "text": text,
                        }
                    ],
                }
            )
        return result

    def chat(self, model: str, history: list[dict[str, str]], system_prompt: str = SYSTEM_PROMPT) -> str:
        payload = {
            "model": model,
            "instructions": system_prompt,
            "input": self.build_input(history),
            "store": False,
            "stream": True,
        }

        for attempt in range(2):
            self.account.ensure_valid()
            try:
                response = requests.post(
                    f"{self.base_url}/responses",
                    headers=self.headers(streaming=True),
                    json=payload,
                    stream=True,
                    timeout=(15, 180),
                )
            except requests.RequestException as exc:
                raise UserVisibleError(f"falha no chat: {safe_exception(exc)}") from exc

            with response:
                if response.status_code == 401 and attempt == 0 and self.account.refresh(force=True):
                    continue
                if not response.ok:
                    raise response_error(response, "falha no chat Codex")

                deltas: list[str] = []
                completed_text = ""
                for raw_line in response.iter_lines(decode_unicode=False):
                    if not raw_line:
                        continue
                    line = raw_line.decode("utf-8", errors="replace")
                    if not line.startswith("data:"):
                        continue
                    raw_event = line[5:].strip()
                    if not raw_event or raw_event == "[DONE]":
                        continue
                    try:
                        event = json.loads(raw_event)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(event, dict):
                        continue
                    event_type = event.get("type")
                    if event_type == "response.output_text.delta" and isinstance(event.get("delta"), str):
                        deltas.append(event["delta"])
                    elif event_type == "response.completed":
                        completed_text = extract_response_text(event.get("response"))
                    elif event_type in {"response.failed", "response.incomplete", "error"}:
                        error = event.get("error") or event.get("response") or "resposta incompleta"
                        if isinstance(error, dict):
                            error = error.get("message") or error.get("code") or "resposta incompleta"
                        raise UserVisibleError(f"o modelo não concluiu a resposta: {redact_secrets(error)}")

                answer = "".join(deltas).strip() or completed_text.strip()
                if not answer:
                    raise UserVisibleError("o modelo terminou sem retornar texto")
                return answer

        raise UserVisibleError("não foi possível autenticar a conta para o chat")

    def _image_request(self, endpoint: str, payload: dict[str, Any]) -> bytes:
        for attempt in range(2):
            self.account.ensure_valid()
            try:
                response = requests.post(
                    f"{self.base_url}/{endpoint}",
                    headers=self.headers(),
                    json=payload,
                    timeout=(15, 360),
                )
            except requests.RequestException as exc:
                raise UserVisibleError(f"falha ao processar imagem: {safe_exception(exc)}") from exc
            if response.status_code == 401 and attempt == 0 and self.account.refresh(force=True):
                response.close()
                continue
            if not response.ok:
                raise response_error(response, "falha ao processar imagem")
            try:
                body = response.json()
                encoded = body["data"][0]["b64_json"]
                return base64.b64decode(encoded, validate=True)
            except (ValueError, KeyError, IndexError, TypeError) as exc:
                raise UserVisibleError("o serviço retornou uma imagem em formato inesperado") from exc
        raise UserVisibleError("não foi possível autenticar a conta para imagens")

    @staticmethod
    def save_image(
        image_bytes: bytes,
        output_file: Path,
        target_width: int | None,
        target_height: int | None,
    ) -> Path:
        output_file = output_file.resolve()
        output_file.parent.mkdir(parents=True, exist_ok=True)
        if target_width is None or target_height is None:
            output_file.write_bytes(image_bytes)
            return output_file
        try:
            with Image.open(io.BytesIO(image_bytes)) as source:
                source.load()
                converted = source.convert("RGBA" if "A" in source.getbands() else "RGB")
                resized = converted.resize((target_width, target_height), Image.Resampling.LANCZOS)
                resized.save(output_file, format="PNG")
        except (UnidentifiedImageError, OSError) as exc:
            raise UserVisibleError("não foi possível redimensionar a imagem retornada") from exc
        return output_file

    def generate_image(
        self,
        prompt: str,
        output_file: Path,
        size: str,
        quality: str,
        background: str,
        target_width: int | None = None,
        target_height: int | None = None,
    ) -> Path:
        image_bytes = self._image_request(
            "images/generations",
            {
                "model": IMAGE_MODEL,
                "prompt": prompt,
                "size": size,
                "quality": quality,
                "background": background,
            },
        )
        return self.save_image(image_bytes, output_file, target_width, target_height)

    def edit_image(
        self,
        prompt: str,
        image_path: Path,
        output_file: Path,
        size: str,
        quality: str,
        background: str,
        target_width: int | None = None,
        target_height: int | None = None,
    ) -> Path:
        if not image_path.is_file():
            raise UserVisibleError("a imagem de referência não foi encontrada")
        if image_path.stat().st_size > 25 * 1024 * 1024:
            raise UserVisibleError("a imagem de referência excede 25 MB")
        image_bytes = image_path.read_bytes()
        suffix = image_path.suffix.lower()
        mime = "image/png" if suffix == ".png" else "image/jpeg"
        encoded = base64.b64encode(image_bytes).decode("ascii")
        result = self._image_request(
            "images/edits",
            {
                "model": IMAGE_MODEL,
                "prompt": prompt,
                "images": [{"image_url": f"data:{mime};base64,{encoded}"}],
                "size": size,
                "quality": quality,
                "background": background,
            },
        )
        return self.save_image(result, output_file, target_width, target_height)


# ---------------------------------------------------------------------------
# Device code e PKCE
# ---------------------------------------------------------------------------


def auth_headers() -> dict[str, str]:
    return {
        "Accept": "application/json",
        "User-Agent": f"{APP_NAME}/{APP_VERSION}",
        "originator": OAUTH_ORIGINATOR,
    }


@dataclass(frozen=True)
class DeviceAuthorization:
    user_code: str
    device_auth_id: str
    verification_url: str
    interval: int
    expires_at: float


def request_device_code() -> DeviceAuthorization:
    try:
        response = requests.post(
            DEVICE_USERCODE_URL,
            json={"client_id": OAUTH_CLIENT_ID},
            headers={**auth_headers(), "Content-Type": "application/json"},
            timeout=(10, 30),
        )
    except requests.RequestException as exc:
        raise UserVisibleError(f"falha ao solicitar device code: {safe_exception(exc)}") from exc

    if response.status_code == 404:
        raise UserVisibleError(
            "device code não está habilitado para esta conta/workspace; "
            "ative-o nas configurações de segurança do ChatGPT ou use PKCE/importação"
        )
    if not response.ok:
        raise response_error(response, "falha ao solicitar device code")
    try:
        body = response.json()
        user_code = str(body["user_code"]).strip()
        device_auth_id = str(body["device_auth_id"]).strip()
        interval = int(str(body.get("interval", "5")).strip())
    except (ValueError, KeyError, TypeError) as exc:
        raise UserVisibleError("o serviço retornou um device code inválido") from exc
    if not user_code or not device_auth_id:
        raise UserVisibleError("o serviço não retornou os dados completos do device code")
    return DeviceAuthorization(
        user_code=user_code,
        device_auth_id=device_auth_id,
        verification_url=DEVICE_VERIFICATION_URL,
        interval=max(1, min(30, interval)),
        expires_at=time.time() + 15 * 60,
    )


def exchange_authorization_code(code: str, verifier: str, redirect_uri: str) -> TokenBundle:
    if not code or not verifier:
        raise UserVisibleError("código ou verificador PKCE ausente")
    try:
        response = requests.post(
            OAUTH_TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": OAUTH_CLIENT_ID,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": redirect_uri,
            },
            headers={**auth_headers(), "Content-Type": "application/x-www-form-urlencoded"},
            timeout=(10, 30),
        )
    except requests.RequestException as exc:
        raise UserVisibleError(f"falha ao trocar o código por tokens: {safe_exception(exc)}") from exc
    if not response.ok:
        raise response_error(response, "falha ao trocar o código por tokens")
    try:
        body = response.json()
    except ValueError as exc:
        raise UserVisibleError("o login retornou uma resposta inválida") from exc
    bundle = bundle_from_mapping(body)
    if not bundle:
        raise UserVisibleError("o login não retornou access_token")
    return bundle


def poll_device_code(device: DeviceAuthorization, cancel_event: threading.Event) -> TokenBundle:
    while time.time() < device.expires_at:
        if cancel_event.is_set():
            raise LoginCancelled("login cancelado")
        try:
            response = requests.post(
                DEVICE_TOKEN_URL,
                json={
                    "device_auth_id": device.device_auth_id,
                    "user_code": device.user_code,
                },
                headers={**auth_headers(), "Content-Type": "application/json"},
                timeout=(10, 30),
            )
        except requests.RequestException as exc:
            if cancel_event.wait(device.interval):
                raise LoginCancelled("login cancelado") from exc
            continue

        if response.ok:
            try:
                body = response.json()
                authorization_code = str(body["authorization_code"]).strip()
                verifier = str(body["code_verifier"]).strip()
            except (ValueError, KeyError, TypeError) as exc:
                raise UserVisibleError("a aprovação do device code retornou dados incompletos") from exc
            return exchange_authorization_code(
                authorization_code,
                verifier,
                DEVICE_REDIRECT_URI,
            )

        # O endpoint oficial usa 403/404 enquanto a aprovação ainda está pendente.
        if response.status_code not in {403, 404}:
            raise response_error(response, "device code recusado")
        if cancel_event.wait(device.interval):
            raise LoginCancelled("login cancelado")

    raise UserVisibleError("o device code expirou após 15 minutos; inicie outro login")


def generate_pkce() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii").rstrip("=")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


def build_browser_login_url(challenge: str, state: str) -> str:
    params = {
        "response_type": "code",
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": BROWSER_REDIRECT_URI,
        "scope": BROWSER_SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "originator": OAUTH_ORIGINATOR,
    }
    return f"{BROWSER_AUTH_URL}?{urlencode(params)}"


def parse_browser_callback(url: str, expected_state: str) -> str:
    try:
        parsed = urlsplit(url.strip())
    except ValueError as exc:
        raise UserVisibleError("URL de callback inválida") from exc
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise UserVisibleError("o callback precisa ser a URL localhost fornecida pelo login")
    if parsed.path != "/auth/callback":
        raise UserVisibleError("a URL não aponta para /auth/callback")
    query = parse_qs(parsed.query)
    if query.get("error"):
        detail = query.get("error_description", query["error"])[0]
        raise UserVisibleError(f"login recusado: {redact_secrets(detail)}")
    state = query.get("state", [""])[0]
    if not state or not secrets.compare_digest(state, expected_state):
        raise UserVisibleError("state do callback não confere; reinicie o login PKCE")
    code = query.get("code", [""])[0].strip()
    if not code:
        raise UserVisibleError("a URL de callback não contém code")
    return code


# ---------------------------------------------------------------------------
# Sessões e helpers do Telegram
# ---------------------------------------------------------------------------


SUPPORTED_API_SIZES = {"1024x1024", "1536x1024", "1024x1536"}


def closest_api_size(width: int, height: int) -> str:
    if width == height:
        return "1024x1024"
    return "1536x1024" if width > height else "1024x1536"


@dataclass
class UserSession:
    account_identity: str | None = None
    account: CodexAccount | None = None
    client: CodexClient | None = None
    history: list[dict[str, str]] = field(default_factory=list)
    preferred_model: str = DEFAULT_MODEL
    state: str | None = None
    pending_prompt: str = ""
    pending_count: int = 1
    pending_reference_path: Path | None = None
    pending_size: str = "1536x1024"
    pending_quality: str = "auto"
    pending_background: str = "auto"
    pending_target_width: int | None = None
    pending_target_height: int | None = None
    pkce_verifier: str | None = None
    pkce_state: str | None = None
    pkce_expires_at: float | None = None
    device_nonce: str | None = None
    device_cancel_event: threading.Event | None = None
    device_task: asyncio.Task[Any] | None = None
    busy_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def select_account(self, account: CodexAccount) -> None:
        self.account = account
        self.account_identity = account.identity
        self.client = CodexClient(account)

    def reset_image_flow(self) -> None:
        self.state = None
        self.pending_prompt = ""
        self.pending_count = 1
        self.pending_reference_path = None
        self.pending_size = "1536x1024"
        self.pending_quality = "auto"
        self.pending_background = "auto"
        self.pending_target_width = None
        self.pending_target_height = None


sessions: dict[int, UserSession] = {}


def get_session(user_id: int) -> UserSession:
    return sessions.setdefault(user_id, UserSession())


def load_accounts() -> list[CodexAccount]:
    return AuthManager().load_accounts()


def ensure_client(session: UserSession) -> bool:
    if session.client and session.account:
        return True
    accounts = load_accounts()
    if not accounts:
        return False
    selected = next(
        (account for account in accounts if account.identity == session.account_identity),
        accounts[0],
    )
    session.select_account(selected)
    return True


def select_saved_identity(session: UserSession, identity: str) -> None:
    account = next((item for item in load_accounts() if item.identity == identity), None)
    if account:
        session.select_account(account)


async def check_access(update: Update) -> bool:
    user = update.effective_user
    if not user:
        return False
    if ALLOWED_TELEGRAM_USER_IDS and user.id not in ALLOWED_TELEGRAM_USER_IDS:
        if update.effective_message:
            await update.effective_message.reply_text("Este bot é privado e seu usuário não está autorizado.")
        return False
    return True


def split_text(text: str, limit: int = 4000) -> list[str]:
    text = text or ""
    chunks: list[str] = []
    while len(text) > limit:
        split_at = text.rfind("\n", 0, limit)
        if split_at < limit // 2:
            split_at = text.rfind(" ", 0, limit)
        if split_at < limit // 2:
            split_at = limit
        chunks.append(text[:split_at].rstrip())
        text = text[split_at:].lstrip()
    if text or not chunks:
        chunks.append(text)
    return chunks


async def send_text(
    update: Update,
    text: str,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> None:
    message = update.effective_message
    if not message:
        return
    chunks = split_text(text)
    for index, chunk in enumerate(chunks):
        await message.reply_text(
            chunk,
            reply_markup=reply_markup if index == len(chunks) - 1 else None,
            disable_web_page_preview=True,
        )


async def send_bot_text(bot: Any, chat_id: int, text: str) -> None:
    for chunk in split_text(text):
        await bot.send_message(chat_id=chat_id, text=chunk, disable_web_page_preview=True)


async def send_photo_path(update: Update, path: Path, caption: str = "") -> None:
    message = update.effective_message
    if not message:
        return
    try:
        with path.open("rb") as stream:
            await message.reply_photo(photo=stream, caption=caption[:1024])
    except TelegramError:
        with path.open("rb") as stream:
            await message.reply_document(document=stream, caption=caption[:1024])


# ---------------------------------------------------------------------------
# Comandos básicos e gerenciamento de contas
# ---------------------------------------------------------------------------


def main_panel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("🖼️ Gerar imagem", callback_data="panel:generate"),
                InlineKeyboardButton("✏️ Editar foto", callback_data="panel:edit"),
            ],
            [
                InlineKeyboardButton("💬 Conversar", callback_data="panel:chat"),
                InlineKeyboardButton("📊 Ver quota", callback_data="panel:status"),
            ],
            [
                InlineKeyboardButton("👤 Minhas contas", callback_data="panel:accounts"),
                InlineKeyboardButton("🔐 Adicionar conta", callback_data="panel:login"),
            ],
            [
                InlineKeyboardButton("📥 Importar JSON", callback_data="panel:import"),
                InlineKeyboardButton("🧹 Limpar chat", callback_data="panel:clear"),
            ],
            [
                InlineKeyboardButton("❌ Cancelar fluxo", callback_data="flow:cancel"),
                InlineKeyboardButton("ℹ️ Ajuda", callback_data="panel:help"),
            ],
            [InlineKeyboardButton("🔄 Atualizar painel", callback_data="panel:home")],
        ]
    )


def panel_navigation_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("⬅️ Painel", callback_data="panel:home"),
                InlineKeyboardButton("❌ Cancelar", callback_data="flow:cancel"),
            ]
        ]
    )


def account_selection_keyboard(accounts: list[CodexAccount]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for index, account in enumerate(accounts, start=1):
        label = account.label if len(account.label) <= 28 else f"{account.label[:25]}..."
        rows.append(
            [InlineKeyboardButton(f"{index}. {label}", callback_data=f"account:select:{index}")]
        )
    rows.append([InlineKeyboardButton("⬅️ Painel principal", callback_data="panel:home")])
    return InlineKeyboardMarkup(rows)


async def show_main_panel(
    update: Update,
    session: UserSession,
    notice: str = "",
) -> None:
    accounts = load_accounts()
    ensure_client(session)
    if session.account:
        account_text = (
            f"{session.account.label}\n"
            f"{session.account.email} • {plan_label(session.account.plan_type)}"
        )
    else:
        account_text = "Nenhuma conta conectada"
    prefix = f"{notice}\n\n" if notice else ""
    await send_text(
        update,
        f"{prefix}🎛️ PAINEL PRINCIPAL\n\n"
        f"👤 Conta atual:\n{account_text}\n\n"
        f"📁 Contas salvas: {len(accounts)}\n"
        "Escolha uma ação nos botões abaixo:",
        reply_markup=main_panel_keyboard(),
    )


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    await show_main_panel(
        update,
        get_session(update.effective_user.id),
        notice="👋 Bem-vindo ao Codex Telegram.",
    )


async def cmd_painel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    await show_main_panel(update, get_session(update.effective_user.id))


async def cmd_ajuda(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    await send_text(
        update,
        "ℹ️ AJUDA RÁPIDA\n\n"
        "Use os botões do /painel ou continue usando comandos:\n\n"
        "/imagem <prompt> — abre as opções de imagem\n"
        "/imagem auto <prompt> — gera horizontal automaticamente\n"
        f"/imagem auto <n> <prompt> — gera até {MAX_IMAGES}\n"
        "/contas e /usar <n> — gerenciar contas\n"
        "/status — consultar quota\n"
        "/login ou /importar — adicionar conta\n"
        "/limpar — limpar histórico\n"
        "/cancelar — cancelar o fluxo atual\n\n"
        "💬 Para conversar, basta enviar uma mensagem.\n"
        "✏️ Para editar, envie uma foto e depois descreva a alteração.",
        reply_markup=panel_navigation_keyboard(),
    )


async def cmd_contas(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    session = get_session(update.effective_user.id)
    accounts = load_accounts()
    if not accounts:
        keyboard = InlineKeyboardMarkup(
            [
                [InlineKeyboardButton("🔐 Adicionar conta", callback_data="panel:login")],
                [InlineKeyboardButton("📥 Importar JSON", callback_data="panel:import")],
                [InlineKeyboardButton("⬅️ Painel", callback_data="panel:home")],
            ]
        )
        await send_text(
            update,
            "Nenhuma conta encontrada em DATA_DIR. Escolha como adicionar:",
            reply_markup=keyboard,
        )
        return
    lines = ["Contas disponíveis:"]
    for index, account in enumerate(accounts, start=1):
        marker = "→" if account.identity == session.account_identity else " "
        lines.extend(
            [
                f"{marker} {index}. {account.label}",
                f"   {account.email} | {plan_label(account.plan_type)}",
                f"   expira: {format_expiration(account.access_token)} | arquivo: {account.auth_file.name}",
            ]
        )
    await send_text(update, "\n".join(lines), reply_markup=account_selection_keyboard(accounts))


async def cmd_usar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    if not context.args:
        await send_text(update, "Uso: /usar <número>. Consulte os números com /contas.")
        return
    try:
        index = int(context.args[0])
    except ValueError:
        await send_text(update, "O número da conta é inválido.")
        return
    accounts = load_accounts()
    if index < 1 or index > len(accounts):
        await send_text(update, f"Escolha uma conta entre 1 e {len(accounts)}.")
        return
    session = get_session(update.effective_user.id)
    session.select_account(accounts[index - 1])
    session.history.clear()
    await send_text(
        update,
        f"Conta selecionada: {session.account.label}\n"
        f"{session.account.email} | {plan_label(session.account.plan_type)}",
    )


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    session = get_session(update.effective_user.id)
    if not ensure_client(session):
        await send_text(update, "Nenhuma conta disponível. Use /login.")
        return
    await send_text(update, "Consultando quota...")
    quota = await asyncio.to_thread(session.account.check_quota)
    five = quota.get("five_hour_pct")
    weekly = quota.get("weekly_pct")
    five_text = f"{five:.0f}% disponível" if isinstance(five, (int, float)) else "não informado"
    weekly_text = f"{weekly:.0f}% disponível" if isinstance(weekly, (int, float)) else "não informado"
    lines = [
        f"Conta: {session.account.label}",
        f"E-mail: {session.account.email}",
        f"Plano: {plan_label(session.account.plan_type)}",
        f"Janela curta: {five_text}",
        f"Reinicia em: {format_remaining(quota.get('five_hour_reset'))}",
        f"Janela semanal: {weekly_text}",
        f"Reinicia em: {format_remaining(quota.get('weekly_reset'))}",
    ]
    if quota.get("error"):
        lines.append(f"Erro: {quota['error']}")
    await send_text(update, "\n".join(lines), reply_markup=panel_navigation_keyboard())


async def cmd_limpar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    get_session(update.effective_user.id).history.clear()
    await send_text(
        update,
        "🧹 Histórico de chat apagado.",
        reply_markup=panel_navigation_keyboard(),
    )


# ---------------------------------------------------------------------------
# Login: device code, PKCE e importação JSON
# ---------------------------------------------------------------------------


def login_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Device Code", callback_data="login:device")],
            [InlineKeyboardButton("Navegador (PKCE)", callback_data="login:pkce")],
            [InlineKeyboardButton("Importar arquivo .json", callback_data="login:import")],
            [
                InlineKeyboardButton("⬅️ Painel", callback_data="panel:home"),
                InlineKeyboardButton("Cancelar fluxo", callback_data="flow:cancel"),
            ],
        ]
    )


async def cmd_login(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    await send_text(
        update,
        "Escolha como adicionar a conta. Nunca envie seu auth.json para outra pessoa ou outro bot.",
        reply_markup=login_keyboard(),
    )


async def start_import_login(update: Update, session: UserSession) -> None:
    session.state = "awaiting_auth_json"
    await send_text(
        update,
        "Importar conta\n\n"
        "Envie agora um documento com extensão .json. São aceitos auth.json do Codex CLI, "
        "credential_pool e objetos com access_token. O arquivo será validado e salvo em DATA_DIR "
        "com nome authN.json.\n\n"
        "Atenção: o documento contém credenciais equivalentes a uma senha.",
        reply_markup=panel_navigation_keyboard(),
    )


async def cmd_importar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    await start_import_login(update, get_session(update.effective_user.id))


async def complete_device_login(
    application: Application,
    user_id: int,
    chat_id: int,
    nonce: str,
    device: DeviceAuthorization,
    cancel_event: threading.Event,
) -> None:
    try:
        bundle = await asyncio.to_thread(poll_device_code, device, cancel_event)
        result = await asyncio.to_thread(save_token_bundle, bundle)
        session = get_session(user_id)
        if session.device_nonce != nonce:
            return
        select_saved_identity(session, result.identity)
        session.state = None
        await send_bot_text(
            application.bot,
            chat_id,
            f"Login concluído. Conta {result.label} {result.action} em {result.path.name}.",
        )
    except LoginCancelled:
        await send_bot_text(application.bot, chat_id, "Login por device code cancelado.")
    except Exception as exc:
        logger.warning("Device code falhou para user_id=%s: %s", user_id, safe_exception(exc))
        await send_bot_text(
            application.bot,
            chat_id,
            f"Erro no device code: {safe_exception(exc)}",
        )
    finally:
        session = get_session(user_id)
        if session.device_nonce == nonce:
            session.device_nonce = None
            session.device_cancel_event = None
            session.device_task = None
            if session.state == "awaiting_device_approval":
                session.state = None


async def start_device_login(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    session: UserSession,
) -> None:
    if session.device_task and not session.device_task.done():
        await send_text(update, "Já existe um login por device code aguardando. Use /cancelar primeiro.")
        return
    await send_text(update, "Solicitando um código de dispositivo...")
    try:
        device = await asyncio.to_thread(request_device_code)
    except Exception as exc:
        await send_text(update, f"Não foi possível iniciar o device code: {safe_exception(exc)}")
        return

    nonce = uuid.uuid4().hex
    cancel_event = threading.Event()
    session.state = "awaiting_device_approval"
    session.device_nonce = nonce
    session.device_cancel_event = cancel_event

    keyboard = InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Abrir página de autorização", url=device.verification_url)],
            [InlineKeyboardButton("Cancelar", callback_data="flow:cancel")],
        ]
    )
    await send_text(
        update,
        "Login por Device Code\n\n"
        f"1. Abra {device.verification_url}\n"
        f"2. Digite este código: {device.user_code}\n"
        "3. Confirme que foi você quem iniciou este login.\n\n"
        "O código expira em 15 minutos. Se a conta ou o workspace bloquear device code, "
        "ative essa opção nas configurações de segurança ou use PKCE/importação.",
        reply_markup=keyboard,
    )
    task = context.application.create_task(
        complete_device_login(
            context.application,
            update.effective_user.id,
            update.effective_chat.id,
            nonce,
            device,
            cancel_event,
        ),
        update=update,
        name=f"device-login-{update.effective_user.id}",
    )
    session.device_task = task


async def start_pkce_login(update: Update, session: UserSession) -> None:
    verifier, challenge = generate_pkce()
    state = secrets.token_urlsafe(24)
    auth_url = build_browser_login_url(challenge, state)
    session.state = "awaiting_browser_callback"
    session.pkce_verifier = verifier
    session.pkce_state = state
    session.pkce_expires_at = time.time() + 10 * 60
    keyboard = InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Abrir login da OpenAI", url=auth_url)],
            [InlineKeyboardButton("Cancelar", callback_data="flow:cancel")],
        ]
    )
    await send_text(
        update,
        "Login PKCE\n\n"
        "1. Abra o botão abaixo e conclua o login.\n"
        "2. O navegador tentará abrir localhost e poderá mostrar erro de conexão; isso é esperado.\n"
        "3. Copie a URL completa da barra de endereço.\n"
        "4. Envie a URL aqui diretamente ou com /callback <url>.\n\n"
        "O callback expira em 10 minutos e o parâmetro state será validado.",
        reply_markup=keyboard,
    )


async def process_browser_callback(update: Update, session: UserSession, url: str) -> None:
    if session.state != "awaiting_browser_callback":
        await send_text(update, "Não existe login PKCE pendente. Use /login primeiro.")
        return
    if not session.pkce_verifier or not session.pkce_state:
        await send_text(update, "Os dados do PKCE foram perdidos. Reinicie o login.")
        return
    if not session.pkce_expires_at or time.time() > session.pkce_expires_at:
        session.state = None
        session.pkce_verifier = None
        session.pkce_state = None
        await send_text(update, "O login PKCE expirou. Inicie outro com /login.")
        return
    try:
        code = parse_browser_callback(url, session.pkce_state)
    except UserVisibleError as exc:
        await send_text(update, f"Callback inválido: {safe_exception(exc)}")
        return

    await send_text(update, "Trocando o código PKCE por tokens...")
    try:
        bundle = await asyncio.to_thread(
            exchange_authorization_code,
            code,
            session.pkce_verifier,
            BROWSER_REDIRECT_URI,
        )
        result = await asyncio.to_thread(save_token_bundle, bundle)
    except Exception as exc:
        await send_text(update, f"Erro ao concluir PKCE: {safe_exception(exc)}")
        return

    session.state = None
    session.pkce_verifier = None
    session.pkce_state = None
    session.pkce_expires_at = None
    select_saved_identity(session, result.identity)
    await send_text(
        update,
        f"Login concluído. Conta {result.label} {result.action} em {result.path.name}.",
    )


async def cmd_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    if not context.args:
        await send_text(update, "Uso: /callback <URL completa de localhost>")
        return
    await process_browser_callback(
        update,
        get_session(update.effective_user.id),
        " ".join(context.args).strip(),
    )


async def cancel_flow(update: Update, session: UserSession) -> None:
    if session.device_cancel_event:
        session.device_cancel_event.set()
    session.device_nonce = None
    session.pkce_verifier = None
    session.pkce_state = None
    session.pkce_expires_at = None
    session.reset_image_flow()
    await send_text(
        update,
        "❌ Fluxo atual cancelado.",
        reply_markup=panel_navigation_keyboard(),
    )


async def cmd_cancelar(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    await cancel_flow(update, get_session(update.effective_user.id))


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    session = get_session(update.effective_user.id)
    if session.state != "awaiting_auth_json":
        await send_text(update, "Para importar JSON, use /login e toque em Importar arquivo .json.")
        return
    document = update.effective_message.document
    filename = document.file_name or ""
    if not filename.lower().endswith(".json"):
        await send_text(update, "Envie um documento cujo nome termine em .json.")
        return
    if document.file_size and document.file_size > MAX_AUTH_JSON_BYTES:
        await send_text(update, f"O JSON excede o limite de {MAX_AUTH_JSON_BYTES // 1024} KB.")
        return

    await send_text(update, "Validando o arquivo JSON...")
    try:
        telegram_file = await context.bot.get_file(document.file_id)
        content = bytes(await telegram_file.download_as_bytearray())
        if len(content) > MAX_AUTH_JSON_BYTES:
            raise UserVisibleError(f"o JSON excede {MAX_AUTH_JSON_BYTES // 1024} KB")
        data = json.loads(content.decode("utf-8-sig"))
        results = await asyncio.to_thread(save_auth_data, data)
    except (UnicodeError, json.JSONDecodeError) as exc:
        await send_text(update, f"JSON inválido: {safe_exception(exc)}")
        return
    except Exception as exc:
        await send_text(update, f"Não foi possível importar: {safe_exception(exc)}")
        return

    session.state = None
    if results:
        select_saved_identity(session, results[0].identity)
    lines = [f"Importação concluída: {len(results)} conta(s)."]
    for result in results:
        lines.append(f"• {result.label}: {result.action} em {result.path.name}")
    lines.append("Use /contas para conferir e /usar <número> para trocar.")
    await send_text(update, "\n".join(lines), reply_markup=main_panel_keyboard())


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    session = get_session(update.effective_user.id)
    text = (update.effective_message.text or "").strip()
    if not text:
        return

    # Estados de login precisam funcionar mesmo quando ainda não há conta.
    if session.state == "awaiting_browser_callback":
        await process_browser_callback(update, session, text)
        return
    if session.state == "awaiting_auth_json":
        await send_text(update, "Estou aguardando um documento .json, não uma mensagem de texto.")
        return
    if session.state == "awaiting_device_approval":
        await send_text(update, "Ainda aguardo a aprovação do device code. Use /cancelar para desistir.")
        return
    if session.state == "awaiting_image_prompt":
        if not ensure_client(session):
            await send_text(update, "Nenhuma conta disponível. Use /login primeiro.")
            return
        if len(text) > MAX_CHAT_CHARS:
            await send_text(update, "O prompt da imagem é grande demais.")
            return
        session.pending_prompt = text
        session.pending_count = 1
        session.pending_reference_path = None
        session.state = None
        reset_image_options(session)
        await ask_image_size(update, session)
        return
    if session.state == "awaiting_photo":
        await send_text(
            update,
            "Estou aguardando uma foto. Use o clipe/câmera do Telegram para enviá-la.",
            reply_markup=panel_navigation_keyboard(),
        )
        return
    if session.state == "awaiting_custom_size":
        await handle_custom_size(update, context)
        return
    if session.state == "awaiting_edit_prompt":
        await process_edit_prompt(update, session, text)
        return

    if not ensure_client(session):
        await send_text(update, "Nenhuma conta disponível. Use /login primeiro.")
        return
    if len(text) > MAX_CHAT_CHARS:
        await send_text(update, f"A mensagem excede o limite de {MAX_CHAT_CHARS} caracteres.")
        return
    if session.busy_lock.locked():
        await send_text(update, "Já existe uma operação em andamento para sua sessão.")
        return

    async with session.busy_lock:
        session.history.append({"role": "user", "content": text})
        session.history[:] = session.history[-MAX_HISTORY_MESSAGES:]
        await send_text(update, "Pensando...")
        try:
            answer = await asyncio.to_thread(
                session.client.chat,
                session.preferred_model,
                list(session.history),
                SYSTEM_PROMPT,
            )
        except Exception as exc:
            if session.history and session.history[-1].get("role") == "user":
                session.history.pop()
            await send_text(update, f"Erro no chat: {safe_exception(exc)}")
            return
        session.history.append({"role": "assistant", "content": answer})
        session.history[:] = session.history[-MAX_HISTORY_MESSAGES:]
        await send_text(update, answer)


# ---------------------------------------------------------------------------
# Geração e edição de imagens
# ---------------------------------------------------------------------------


def reset_image_options(session: UserSession) -> None:
    session.pending_size = "1536x1024"
    session.pending_quality = "auto"
    session.pending_background = "auto"
    session.pending_target_width = None
    session.pending_target_height = None


async def ask_image_size(update: Update, session: UserSession) -> None:
    keyboard = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton(
                    "⚡ Automático horizontal",
                    callback_data="image:auto",
                )
            ],
            [InlineKeyboardButton("Quadrado 1024x1024", callback_data="size:1024x1024")],
            [InlineKeyboardButton("Horizontal 1536x1024", callback_data="size:1536x1024")],
            [InlineKeyboardButton("Vertical 1024x1536", callback_data="size:1024x1536")],
            [InlineKeyboardButton("Tamanho personalizado", callback_data="size:custom")],
            [
                InlineKeyboardButton("⬅️ Painel", callback_data="panel:home"),
                InlineKeyboardButton("Cancelar", callback_data="flow:cancel"),
            ],
        ]
    )
    await send_text(
        update,
        f"Configuração de imagem\nPrompt: {session.pending_prompt}\n"
        f"Quantidade: {session.pending_count}\n\nEscolha o tamanho:",
        reply_markup=keyboard,
    )


async def ask_image_quality(update: Update) -> None:
    keyboard = InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Automática", callback_data="quality:auto")],
            [InlineKeyboardButton("Alta", callback_data="quality:high")],
            [InlineKeyboardButton("Média", callback_data="quality:medium")],
            [InlineKeyboardButton("Baixa", callback_data="quality:low")],
            [
                InlineKeyboardButton("⬅️ Painel", callback_data="panel:home"),
                InlineKeyboardButton("Cancelar", callback_data="flow:cancel"),
            ],
        ]
    )
    await send_text(update, "Escolha a qualidade:", reply_markup=keyboard)


async def ask_image_background(update: Update) -> None:
    keyboard = InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("Automático", callback_data="background:auto")],
            [InlineKeyboardButton("Transparente", callback_data="background:transparent")],
            [InlineKeyboardButton("Branco", callback_data="background:white")],
            [InlineKeyboardButton("Preto", callback_data="background:black")],
            [
                InlineKeyboardButton("⬅️ Painel", callback_data="panel:home"),
                InlineKeyboardButton("Cancelar", callback_data="flow:cancel"),
            ],
        ]
    )
    await send_text(update, "Escolha o fundo:", reply_markup=keyboard)


def parse_image_command(rest: str) -> tuple[bool, int, str]:
    """Interpreta /imagem [auto] [quantidade] prompt."""
    parts = rest.split()
    automatic = bool(parts and parts[0].lower() == "auto")
    if automatic:
        parts.pop(0)
    count = 1
    if parts and parts[0].isdigit():
        count = int(parts.pop(0))
    return automatic, count, " ".join(parts).strip()


async def schedule_automatic_image(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    session: UserSession,
    task_name: str,
) -> bool:
    if not session.pending_prompt:
        await send_text(update, "O pedido de imagem expirou. Inicie novamente pelo painel.")
        return False
    if session.state == "image_generating" or session.busy_lock.locked():
        await send_text(update, "Já existe uma operação em andamento para sua sessão.")
        return False
    reset_image_options(session)
    session.state = "image_generating"
    await send_text(
        update,
        "⚡ Modo automático: horizontal 1536x1024, qualidade automática e fundo automático.",
    )
    context.application.create_task(
        generate_images(update, session, update.effective_user.id),
        update=update,
        name=task_name,
    )
    return True


async def cmd_imagem(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    session = get_session(update.effective_user.id)
    if not ensure_client(session):
        await send_text(update, "Nenhuma conta disponível. Use /login primeiro.")
        return
    rest = " ".join(context.args).strip()
    automatic, count, prompt = parse_image_command(rest)
    if count < 1 or count > MAX_IMAGES:
        await send_text(update, f"A quantidade precisa ficar entre 1 e {MAX_IMAGES}.")
        return
    if not prompt:
        await send_text(
            update,
            "Uso: /imagem <descrição>, /imagem <n> <descrição> ou /imagem auto <descrição>.",
        )
        return
    if len(prompt) > MAX_CHAT_CHARS:
        await send_text(update, "O prompt da imagem é grande demais.")
        return
    session.pending_prompt = prompt
    session.pending_count = count
    session.pending_reference_path = None
    reset_image_options(session)
    if automatic:
        await schedule_automatic_image(
            update,
            context,
            session,
            task_name=f"automatic-image-generation-{update.effective_user.id}",
        )
        return
    await ask_image_size(update, session)


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    session = get_session(update.effective_user.id)
    if not ensure_client(session):
        await send_text(update, "Nenhuma conta disponível. Use /login primeiro.")
        return
    if session.busy_lock.locked():
        await send_text(update, "Já existe uma operação em andamento para sua sessão.")
        return
    photo = update.effective_message.photo[-1]
    try:
        telegram_file = await context.bot.get_file(photo.file_id)
        content = bytes(await telegram_file.download_as_bytearray())
        with Image.open(io.BytesIO(content)) as source:
            source.load()
            image = source.convert("RGBA" if "A" in source.getbands() else "RGB")
        reference = REFERENCES_DIR / f"telegram-{update.effective_user.id}-{uuid.uuid4().hex[:12]}.png"
        image.save(reference, format="PNG")
    except (TelegramError, UnidentifiedImageError, OSError) as exc:
        await send_text(update, f"Não foi possível ler a foto: {safe_exception(exc)}")
        return
    session.pending_reference_path = reference
    session.pending_count = 1
    session.pending_prompt = ""
    reset_image_options(session)
    session.state = "awaiting_edit_prompt"
    await send_text(
        update,
        "✅ Foto recebida. Descreva agora como deseja editá-la.",
        reply_markup=panel_navigation_keyboard(),
    )


async def process_edit_prompt(update: Update, session: UserSession, text: str) -> None:
    if not text:
        await send_text(update, "Descreva a edição desejada.")
        return
    session.pending_prompt = text
    session.state = None
    await ask_image_size(update, session)


async def handle_custom_size(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    session = get_session(update.effective_user.id)
    if session.state != "awaiting_custom_size":
        return
    text = (update.effective_message.text or "").strip()
    match = re.fullmatch(r"(\d{2,5})\s*(?:x|X|,|\s)\s*(\d{2,5})", text)
    if not match:
        await send_text(update, "Formato inválido. Envie, por exemplo: 800x450 ou 800 450.")
        return
    width, height = int(match.group(1)), int(match.group(2))
    if not (
        MIN_CUSTOM_DIMENSION <= width <= MAX_CUSTOM_DIMENSION
        and MIN_CUSTOM_DIMENSION <= height <= MAX_CUSTOM_DIMENSION
    ):
        await send_text(
            update,
            f"Cada dimensão precisa ficar entre {MIN_CUSTOM_DIMENSION} e {MAX_CUSTOM_DIMENSION} pixels.",
        )
        return
    if width * height > MAX_CUSTOM_PIXELS:
        await send_text(update, f"O tamanho excede o limite de {MAX_CUSTOM_PIXELS:,} pixels.")
        return
    session.pending_target_width = width
    session.pending_target_height = height
    session.pending_size = closest_api_size(width, height)
    session.state = None
    await send_text(
        update,
        f"Tamanho final: {width}x{height}. A API gerará {session.pending_size} antes do redimensionamento.",
    )
    await ask_image_quality(update)


async def generate_images(update: Update, session: UserSession, user_id: int) -> None:
    if session.busy_lock.locked():
        if session.state == "image_generating":
            session.state = None
        await send_text(update, "Já existe uma operação em andamento para sua sessão.")
        return
    if not session.client or not session.pending_prompt:
        await send_text(update, "O pedido de imagem expirou. Use /imagem novamente.")
        session.reset_image_flow()
        return

    async with session.busy_lock:
        prompt = session.pending_prompt
        count = session.pending_count
        reference = session.pending_reference_path
        size = session.pending_size
        quality = session.pending_quality
        background = session.pending_background
        target_width = session.pending_target_width
        target_height = session.pending_target_height
        client = session.client
        await send_text(
            update,
            f"Iniciando {'edição' if reference else 'geração'} de {count} imagem(ns)...",
        )

        def generate_one(index: int) -> Path:
            output = IMAGES_DIR / f"telegram-{user_id}-{uuid.uuid4().hex[:16]}-{index + 1}.png"
            if reference:
                return client.edit_image(
                    prompt,
                    reference,
                    output,
                    size,
                    quality,
                    background,
                    target_width,
                    target_height,
                )
            return client.generate_image(
                prompt,
                output,
                size,
                quality,
                background,
                target_width,
                target_height,
            )

        results = await asyncio.gather(
            *(asyncio.to_thread(generate_one, index) for index in range(count)),
            return_exceptions=True,
        )
        successes = 0
        errors: list[str] = []
        for index, result in enumerate(results, start=1):
            if isinstance(result, BaseException):
                errors.append(f"Imagem {index}: {safe_exception(result)}")
                continue
            successes += 1
            await send_photo_path(update, result, caption=f"{index}/{count}: {prompt}")
        session.reset_image_flow()
        if errors:
            await send_text(update, "\n".join(errors), reply_markup=panel_navigation_keyboard())
        if successes:
            await send_text(
                update,
                f"✅ Concluído: {successes}/{count} imagem(ns) enviada(s).",
                reply_markup=panel_navigation_keyboard(),
            )


# ---------------------------------------------------------------------------
# Callbacks, erros e inicialização
# ---------------------------------------------------------------------------


VISUAL_IMAGE_STATES = {
    "awaiting_image_prompt",
    "awaiting_photo",
    "awaiting_edit_prompt",
    "awaiting_custom_size",
}

AUTH_FLOW_STATES = {
    "awaiting_auth_json",
    "awaiting_browser_callback",
    "awaiting_device_approval",
}


def clear_visual_image_flow(session: UserSession) -> None:
    if session.state in VISUAL_IMAGE_STATES:
        session.reset_image_flow()


async def start_visual_image_flow(update: Update, session: UserSession) -> None:
    if session.state in AUTH_FLOW_STATES:
        await send_text(
            update,
            "Há um login/importação pendente. Use Cancelar fluxo antes de gerar uma imagem.",
            reply_markup=panel_navigation_keyboard(),
        )
        return
    if not ensure_client(session):
        await send_text(
            update,
            "Você precisa adicionar uma conta antes de gerar imagens.",
            reply_markup=login_keyboard(),
        )
        return
    session.reset_image_flow()
    session.state = "awaiting_image_prompt"
    await send_text(
        update,
        "🖼️ GERAR IMAGEM\n\nEnvie agora a descrição da imagem que deseja criar.",
        reply_markup=panel_navigation_keyboard(),
    )


async def start_visual_edit_flow(update: Update, session: UserSession) -> None:
    if session.state in AUTH_FLOW_STATES:
        await send_text(
            update,
            "Há um login/importação pendente. Use Cancelar fluxo antes de editar uma foto.",
            reply_markup=panel_navigation_keyboard(),
        )
        return
    if not ensure_client(session):
        await send_text(
            update,
            "Você precisa adicionar uma conta antes de editar fotos.",
            reply_markup=login_keyboard(),
        )
        return
    session.reset_image_flow()
    session.state = "awaiting_photo"
    await send_text(
        update,
        "✏️ EDITAR FOTO\n\nEnvie agora a foto pelo clipe ou pela câmera do Telegram. "
        "Depois eu pedirei o prompt da edição.",
        reply_markup=panel_navigation_keyboard(),
    )


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    query = update.callback_query
    await query.answer()
    session = get_session(update.effective_user.id)
    data = query.data or ""

    if data == "panel:home":
        clear_visual_image_flow(session)
        await show_main_panel(update, session)
        return
    if data == "panel:generate":
        await start_visual_image_flow(update, session)
        return
    if data == "panel:edit":
        await start_visual_edit_flow(update, session)
        return
    if data == "panel:chat":
        if session.state in AUTH_FLOW_STATES:
            await send_text(
                update,
                "Há um login/importação pendente. Conclua ou cancele esse fluxo primeiro.",
                reply_markup=panel_navigation_keyboard(),
            )
            return
        if not ensure_client(session):
            await send_text(update, "Adicione uma conta para conversar.", reply_markup=login_keyboard())
            return
        clear_visual_image_flow(session)
        await send_text(
            update,
            "💬 CHAT\n\nEnvie sua pergunta ou mensagem. As próximas mensagens serão tratadas como chat.",
            reply_markup=panel_navigation_keyboard(),
        )
        return
    if data == "panel:status":
        await cmd_status(update, context)
        return
    if data == "panel:accounts":
        await cmd_contas(update, context)
        return
    if data == "panel:login":
        await cmd_login(update, context)
        return
    if data == "panel:import":
        await start_import_login(update, session)
        return
    if data == "panel:clear":
        session.history.clear()
        await show_main_panel(update, session, notice="🧹 Histórico de chat apagado.")
        return
    if data == "panel:help":
        await cmd_ajuda(update, context)
        return
    if data.startswith("account:select:"):
        try:
            index = int(data.rsplit(":", 1)[1])
        except ValueError:
            await send_text(update, "Seleção de conta inválida.")
            return
        accounts = load_accounts()
        if index < 1 or index > len(accounts):
            await send_text(update, "Essa lista de contas expirou. Abra Minhas contas novamente.")
            return
        session.select_account(accounts[index - 1])
        session.history.clear()
        await show_main_panel(
            update,
            session,
            notice=f"✅ Conta selecionada: {session.account.label}",
        )
        return
    if data == "image:auto":
        await schedule_automatic_image(
            update,
            context,
            session,
            task_name=f"visual-auto-image-{update.effective_user.id}",
        )
        return
    if data == "flow:cancel":
        await cancel_flow(update, session)
        return
    if data == "login:device":
        await start_device_login(update, context, session)
        return
    if data == "login:pkce":
        await start_pkce_login(update, session)
        return
    if data == "login:import":
        await start_import_login(update, session)
        return

    if data.startswith("size:"):
        if not session.pending_prompt:
            await send_text(update, "Este botão expirou. Use /imagem novamente.")
            return
        value = data.split(":", 1)[1]
        if value == "custom":
            session.state = "awaiting_custom_size"
            await send_text(update, "Envie largura e altura, por exemplo: 800x450 ou 800 450.")
            return
        if value not in SUPPORTED_API_SIZES:
            await send_text(update, "Tamanho de API inválido.")
            return
        session.pending_size = value
        session.pending_target_width = None
        session.pending_target_height = None
        await ask_image_quality(update)
        return

    if data.startswith("quality:"):
        value = data.split(":", 1)[1]
        if value not in {"auto", "high", "medium", "low"} or not session.pending_prompt:
            await send_text(update, "Esta seleção de qualidade expirou.")
            return
        session.pending_quality = value
        await ask_image_background(update)
        return

    if data.startswith("background:"):
        value = data.split(":", 1)[1]
        if value not in {"auto", "transparent", "white", "black"} or not session.pending_prompt:
            await send_text(update, "Esta seleção de fundo expirou.")
            return
        if session.state == "image_generating" or session.busy_lock.locked():
            await send_text(update, "Já existe uma operação em andamento para sua sessão.")
            return
        session.pending_background = value
        session.state = "image_generating"
        context.application.create_task(
            generate_images(update, session, update.effective_user.id),
            update=update,
            name=f"image-generation-{update.effective_user.id}",
        )
        return


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.error("Erro não tratado pelo bot: %s", safe_exception(context.error), exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(
                "Ocorreu um erro interno. Consulte os logs sem compartilhar tokens ou auth.json."
            )
        except TelegramError:
            pass


def require_telegram_token() -> str:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not token or token.lower() in {"seu_token_aqui", "changeme"}:
        raise RuntimeError(
            "Defina TELEGRAM_BOT_TOKEN somente como variável de runtime no Coolify."
        )
    return token


async def configure_bot_commands(application: Application) -> None:
    commands = [
        BotCommand("painel", "Abrir o painel visual"),
        BotCommand("imagem", "Gerar imagem"),
        BotCommand("contas", "Listar e selecionar contas"),
        BotCommand("status", "Consultar quota da conta"),
        BotCommand("login", "Adicionar uma conta"),
        BotCommand("importar", "Importar auth.json"),
        BotCommand("limpar", "Limpar histórico do chat"),
        BotCommand("cancelar", "Cancelar o fluxo atual"),
        BotCommand("ajuda", "Ver ajuda e comandos"),
    ]
    try:
        await application.bot.set_my_commands(commands)
    except TelegramError as exc:
        logger.warning("Não foi possível configurar o menu de comandos: %s", safe_exception(exc))


def build_application(token: str) -> Application:
    application = Application.builder().token(token).post_init(configure_bot_commands).build()
    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("painel", cmd_painel))
    application.add_handler(CommandHandler("ajuda", cmd_ajuda))
    application.add_handler(CommandHandler("login", cmd_login))
    application.add_handler(CommandHandler("importar", cmd_importar))
    application.add_handler(CommandHandler("callback", cmd_callback))
    application.add_handler(CommandHandler("cancelar", cmd_cancelar))
    application.add_handler(CommandHandler("contas", cmd_contas))
    application.add_handler(CommandHandler("usar", cmd_usar))
    application.add_handler(CommandHandler("status", cmd_status))
    application.add_handler(CommandHandler("limpar", cmd_limpar))
    application.add_handler(CommandHandler("imagem", cmd_imagem))
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    application.add_error_handler(error_handler)
    return application


def main() -> None:
    token = require_telegram_token()
    logger.info("Iniciando %s v%s", APP_NAME, APP_VERSION)
    logger.info("DATA_DIR=%s", DATA_DIR)
    logger.info("Contas encontradas=%d", len(discover_auth_files()))
    if not ALLOWED_TELEGRAM_USER_IDS:
        logger.warning(
            "ALLOWED_TELEGRAM_USER_IDS não foi definido; qualquer usuário que encontrar o bot poderá usá-lo."
        )
    application = build_application(token)
    application.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
    )


if __name__ == "__main__":
    main()
