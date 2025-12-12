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

# Install nodeseeker/tcping (static build)
# Reference: https://github.com/nodeseeker/tcping
RUN bash <(curl -Ls https://raw.githubusercontent.com/nodeseeker/tcping/main/install.sh) --force

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
