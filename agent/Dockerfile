FROM python:3.12-slim

# Install system dependencies required by the agent
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iputils-ping \
    traceroute \
    wireguard-tools \
    iproute2 \
    bird2 \
    vnstat \
    && rm -rf /var/lib/apt/lists/*

# Note: tcping should be installed separately. 
# You can install it from https://github.com/nodeseeker/tcping or mount it as a volume

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the API port (default 54321)
EXPOSE 54321

# Run the agent
CMD ["python3", "main.py"]
