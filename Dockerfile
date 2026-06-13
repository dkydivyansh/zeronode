FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Expose the requested port
EXPOSE 8862

# Run via Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8862", "--timeout", "120", "--workers", "1", "--threads", "4", "run:app"]
