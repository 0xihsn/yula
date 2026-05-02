FROM python:3.11.9-slim

# Non-root user for security
RUN groupadd -r yulascanner && useradd -r -g yulascanner -m yulascanner

WORKDIR /app

# Install OS deps needed by Playwright and httpx
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    gnupg \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies first (layer cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browser (chromium only — smallest footprint)
RUN playwright install chromium --with-deps || true

# Copy application code
COPY . .

# Create output dir with correct ownership
RUN mkdir -p /app/output && chown -R yulascanner:yulascanner /app/output

USER yulascanner

# Default: show the help menu
ENTRYPOINT ["python", "run.py"]
CMD ["--help"]
