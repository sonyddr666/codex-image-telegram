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
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
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
# -----------------------------------------------…10445 tokens truncated…end_text(
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
    await send_text(update, "Fluxo atual cancelado.")


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
    await send_text(update, "\n".join(lines))


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
            [InlineKeyboardButton("Quadrado 1024x1024", callback_data="size:1024x1024")],
            [InlineKeyboardButton("Horizontal 1536x1024", callback_data="size:1536x1024")],
            [InlineKeyboardButton("Vertical 1024x1536", callback_data="size:1024x1536")],
            [InlineKeyboardButton("Tamanho personalizado", callback_data="size:custom")],
            [InlineKeyboardButton("Cancelar", callback_data="flow:cancel")],
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
            [InlineKeyboardButton("Cancelar", callback_data="flow:cancel")],
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
            [InlineKeyboardButton("Cancelar", callback_data="flow:cancel")],
        ]
    )
    await send_text(update, "Escolha o fundo:", reply_markup=keyboard)


async def cmd_imagem(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    session = get_session(update.effective_user.id)
    if not ensure_client(session):
        await send_text(update, "Nenhuma conta disponível. Use /login primeiro.")
        return
    rest = " ".join(context.args).strip()
    count = 1
    prompt = rest
    if rest:
        first, separator, remaining = rest.partition(" ")
        if first.isdigit():
            count = int(first)
            prompt = remaining.strip() if separator else ""
    if count < 1 or count > MAX_IMAGES:
        await send_text(update, f"A quantidade precisa ficar entre 1 e {MAX_IMAGES}.")
        return
    if not prompt:
        await send_text(update, "Uso: /imagem <descrição> ou /imagem <n> <descrição>.")
        return
    if len(prompt) > MAX_CHAT_CHARS:
        await send_text(update, "O prompt da imagem é grande demais.")
        return
    session.pending_prompt = prompt
    session.pending_count = count
    session.pending_reference_path = None
    reset_image_options(session)
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
    await send_text(update, "Foto recebida. Descreva agora como deseja editá-la.")


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
            await send_text(update, "\n".join(errors))
        if successes:
            await send_text(update, f"Concluído: {successes}/{count} imagem(ns) enviada(s).")


# ---------------------------------------------------------------------------
# Callbacks, erros e inicialização
# ---------------------------------------------------------------------------


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not await check_access(update):
        return
    query = update.callback_query
    await query.answer()
    session = get_session(update.effective_user.id)
    data = query.data or ""

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


def build_application(token: str) -> Application:
    application = Application.builder().token(token).build()
    application.add_handler(CommandHandler("start", cmd_start))
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
