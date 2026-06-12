# Deployment Guide

SentinelMCP supports multiple deployment strategies depending on the operational environment.

## 1. Local Deployment
Ideal for analysts running triage on their local forensic workstations.

```bash
git clone https://github.com/sentinelmcp/sentinelmcp.git
cd sentinelmcp
pip install .
```
Verify installation:
```bash
sentinelmcp -h
```

## 2. Virtual Environment Deployment
Recommended for isolating dependencies.

```bash
python -m venv venv
# Linux/macOS
source venv/bin/activate
# Windows
.\venv\Scripts\activate

pip install .
```

## 3. Docker Deployment (Recommended for Production)
The supplied `Dockerfile` and `docker-compose.yml` configure a hardened, non-root container for the MCP server.

### Build and Run
```bash
# Export your secure API key
export SENTINELMCP_API_KEY="your-secure-key"

# Start the service in the background
docker-compose up -d --build
```

### Container Security Features
- **Non-Root User**: The container executes as the `sentinel` user.
- **Read-Only Root Filesystem**: Controlled via `read_only: true` and `tmpfs` mounts.
- **No New Privileges**: Hardened security options block privilege escalation.
- **Volume Mounts**: Evidence should be placed in `./evidence` which is mapped as `ro` (read-only) internally to prevent data tampering.

## Upgrades
To upgrade an existing installation:
```bash
git pull origin main
pip install --upgrade .
# Or for docker:
docker-compose up -d --build
```
