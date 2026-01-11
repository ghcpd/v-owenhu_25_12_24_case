FROM python:3.12-slim

# Create non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Install runtime dependencies
COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir -r /app/requirements.txt

# Application files
COPY . /app
RUN mkdir -p /app/configs && chown -R appuser:appgroup /app

USER appuser
ENV FLASK_ENV=production
ENV FLASK_DEBUG=0
EXPOSE 5000
CMD ["python", "input.py"]
