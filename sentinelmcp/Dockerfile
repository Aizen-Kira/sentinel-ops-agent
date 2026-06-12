# Use official Python lightweight image
FROM python:3.11-slim

# Create a non-root user
RUN useradd --create-home --shell /bin/bash sentinel

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Copy project files and change ownership
COPY --chown=sentinel:sentinel . /app

# Switch to non-root user
USER sentinel

# Install the application
ENV PATH="/home/sentinel/.local/bin:${PATH}"
RUN pip install --user --no-cache-dir .

# Create directory for evidence mounts
RUN mkdir -p /app/evidence

# Environment variables with safe defaults
ENV SENTINELMCP_MAX_ITERATIONS=8
ENV SENTINELMCP_CACHE_TTL=3600
ENV SENTINELMCP_LOG_LEVEL=INFO
ENV SENTINELMCP_ALLOWED_PATHS=/app/evidence

# Expose MCP SSE default port
EXPOSE 8000

# Entrypoint for the MCP server
CMD ["python", "-m", "mcp_server.server"]
