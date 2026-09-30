# Quantsiv MVP Dockerfile
# Based on the cloud deployment plan from MVP specifications

# Base image with Python 3.12 and OpenJDK 17 for cbomkit-lib
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create directory for cbomkit-lib JAR (would be copied or downloaded in real build)
RUN mkdir -p /app/bin
# In real build: copy cbomkit-lib.jar to /app/bin/
# For MVP structure, we note where it would go

# Create non-root user for security
RUN adduser --disabled-password --gecos '' appuser
USER appuser

# Expose port
EXPOSE 8000

# Environment variables (would be set at runtime)
ENV PORT=8000
ENV HOST=0.0.0.0

# Command to run the application
# In real implementation: use supervisord or similar to run web + worker
# For MVP simplicity, we'll start the web server and note worker would be separate
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]