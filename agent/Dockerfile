# Build stage for tcping
FROM golang:alpine AS tcping-builder

RUN apk add --no-cache git

# Build nodeseeker/tcping from source
RUN set -e; \
    git clone --depth 1 https://github.com/nodeseeker/tcping.git /tmp/tcping && \
    cd /tmp/tcping && \
    GOTOOLCHAIN=auto CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o tcping ./src/main.go

# Final stage
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
    && rm -rf /var/lib/apt/lists/*

# Copy tcping binary from builder stage
COPY --from=tcping-builder /tmp/tcping/tcping /usr/local/bin/tcping
RUN chmod +x /usr/local/bin/tcping

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
