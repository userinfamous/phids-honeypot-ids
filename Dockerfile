# Python Honeypot IDS (PHIDS) Docker Container
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    iputils-ping \
    nmap \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p data logs reports

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose honeypot ports
EXPOSE 2222 8080 2121

# Create non-root user for security
RUN useradd -m -u 1000 phids && \
    chown -R phids:phids /app

# Switch to non-root user
USER phids

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sqlite3; sqlite3.connect('data/phids.db').close()" || exit 1

# Default command
CMD ["python", "main.py"]

# Labels
LABEL maintainer="PHIDS Team"
LABEL description="Python Honeypot IDS - Containerized Security Monitoring"
LABEL version="1.0"
