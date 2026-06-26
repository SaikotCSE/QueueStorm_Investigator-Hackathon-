FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# Install dependencies first for better layer caching on Render
COPY pyproject.toml README.md /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir 'fastapi>=0.115,<1.0' 'uvicorn[standard]>=0.30,<1.0' 'pydantic>=2.8,<3.0'

COPY app /app/app

EXPOSE 8000

# Render sets $PORT; fall back to 8000 for local docker run
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
