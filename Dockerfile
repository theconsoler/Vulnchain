# Base image: Python 3.11 on Debian 12 (bookworm) — pinned, not floating
FROM python:3.11-slim-bookworm

# Set working directory
WORKDIR /app

# Install system dependencies
# WeasyPrint requires pango and cairo
# curl needed for health checks
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
# If requirements.txt does not change, pip install is cached
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app/            ./app/
COPY enrichment/     ./enrichment/
COPY graph/           ./graph/
COPY models/         ./models/
COPY parsers/        ./parsers/
COPY reporting/      ./reporting/
COPY scoring/        ./scoring/
COPY static/         ./static/
COPY templates/      ./templates/
COPY samples/        ./samples/
COPY main.py         .
COPY build_graph.py  .
COPY enrich_graph.py .
COPY score_vulns.py  .
COPY generate_report.py .
COPY run.py          .
COPY create_user.py  .
COPY entrypoint.sh   .

# Make entrypoint executable
RUN chmod +x entrypoint.sh

# Create directories that need to exist at runtime
RUN mkdir -p output uploads cache/nvd cache/epss

# Expose Flask port
EXPOSE 5000

# Health check -- verifies the app is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5000/login || exit 1

# Run entrypoint script
ENTRYPOINT ["./entrypoint.sh"]
