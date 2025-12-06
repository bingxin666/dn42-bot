FROM python:3.12-slim

# Install system dependencies required by the server
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    iputils-ping \
    traceroute \
    dnsutils \
    whois \
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

# Create a config file from example if it doesn't exist
RUN if [ ! -f config.py ]; then cp config.example.py config.py; fi

# Expose the webhook port (default 3443)
EXPOSE 3443

# Run the server
CMD ["python3", "main.py"]
