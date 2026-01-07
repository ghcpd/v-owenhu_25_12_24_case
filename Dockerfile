# Minimal, least-privilege container for the hardened app
FROM python:3.12-slim

# Create non-root user
RUN useradd --create-home --shell /bin/false appuser \
    && apt-get update && apt-get install -y --no-install-recommends \
       build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Install only runtime dependencies
RUN python -m pip install --no-cache-dir -r requirements.txt

# Ensure a non-root runtime
USER appuser

ENV PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    APP_HOST=0.0.0.0

EXPOSE 5000
CMD ["python", "input.py"]
