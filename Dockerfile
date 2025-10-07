# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Install system packages needed for some Python deps (argon2, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -ms /bin/bash appuser

WORKDIR /app

# Copy only requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Ensure data dir exists and owned by appuser
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

ENV FLASK_ENV=development \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5000

# Default command (can be overridden in compose)
CMD ["python", "app.py"]
