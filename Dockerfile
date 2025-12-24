FROM python:3.12-slim

# Create unprivileged user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Install runtime deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . /app

# Ensure data directories exist and are owned by non-root user
RUN mkdir -p /app/configs /app/exports && chown -R appuser:appgroup /app

USER appuser
ENV PATH="/home/appuser/.local/bin:${PATH}"

# Do not enable debug in container by default
ENV FLASK_DEBUG=0
ENV PYTHONUNBUFFERED=1

EXPOSE 5000
CMD ["python", "input.py"]
