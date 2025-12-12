FROM python:3.14-slim

# Install system dependencies required by the agent
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iputils-ping \
    traceroute \
    wireguard-tools \
    iproute2 \
    bird2 \
    vnstat \
    build-essential \
    ca-certificates \
    git \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

# Build and install nodeseeker/tcping from source
# Reference: https://github.com/nodeseeker/tcping
RUN set -e; \
    git clone --depth 1 https://github.com/nodeseeker/tcping.git /tmp/tcping && \
    cd /tmp/tcping && \
    arch=$(dpkg --print-architecture); \
    case "$arch" in \
        amd64)  GOARCH="amd64" ;; \
        arm64)  GOARCH="arm64" ;; \
        armhf)  GOARCH="arm" ;; \
        *)      echo "Unsupported architecture: $arch" && exit 1 ;; \
    esac; \
    CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -trimpath -ldflags="-w -s" -o tcping ./src/main.go && \
    install -m 0755 tcping /usr/local/bin/tcping && \
    cd / && \
    rm -rf /tmp/tcping

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Precompile Python bytecode to avoid compile on first run
RUN python -m compileall -q /app

# Expose the API port (default 54321)
EXPOSE 54321

# Run the agent
CMD ["python3", "main.py"]
