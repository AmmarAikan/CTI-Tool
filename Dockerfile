FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir "torch>=2.5,<3.0" --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend /app/backend
COPY ml/common /app/ml/common
COPY ml/models/dnrti_sklearn_ner /app/ml/models/dnrti_sklearn_ner

RUN useradd --create-home --uid 10001 cti && \
    mkdir -p /app/data/uploads && \
    chown -R cti:cti /app
USER cti

EXPOSE 8000
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
