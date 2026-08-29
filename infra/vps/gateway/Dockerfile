FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system --gid 10001 gateway \
    && useradd --system --uid 10001 --gid gateway --home-dir /nonexistent gateway

COPY requirements.txt ./
RUN python -m pip install --requirement requirements.txt

COPY app.py ./
RUN mkdir -p /data /sensors/dionaea /sensors/host \
    && chown -R 10001:10001 /data

USER 10001:10001
EXPOSE 8080

CMD ["python", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
