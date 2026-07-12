FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data

WORKDIR /app

RUN groupadd --gid 10001 bot \
    && useradd --uid 10001 --gid bot --create-home --shell /usr/sbin/nologin bot \
    && mkdir -p /app/data/imagens /app/data/referencias \
    && chown -R bot:bot /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY --chown=bot:bot codex_telegram_unificado.py ./

USER bot

CMD ["python", "codex_telegram_unificado.py"]
