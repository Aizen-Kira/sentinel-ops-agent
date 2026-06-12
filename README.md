# Sentinel Ops Agent

![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)
![React](https://img.shields.io/badge/React-19-61DAFB)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB)
![MCP](https://img.shields.io/badge/MCP-FastMCP-purple)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

**AI-assisted SOC triage, incident investigation, executive reporting, and MCP-powered digital forensics.**

Sentinel Ops Agent is a full-stack security operations project built for modern incident response teams. It combines a React-based SOC dashboard with a Python FastMCP forensic investigation agent, helping analysts move from alert noise to structured investigation, response review, and executive-ready reporting.

---

## Why This Exists

Security teams often lose critical time switching between alert queues, SIEM searches, investigation notes, AI tools, forensic utilities, and reporting templates.

Sentinel Ops Agent brings those workflows together:

- Triage alerts in a SOC-focused dashboard.
- Investigate incidents with AI-assisted analysis.
- Stream realtime security events into the UI.
- Generate executive and CISO-style briefings.
- Run MCP forensic workflows over disk, memory, packet, cloud, container, and YARA-oriented evidence.
- Preserve human approval for sensitive response actions.

The result is a demo-ready and extensible security operations platform that shows practical value for analysts, technical depth for engineers, and clear impact for hackathon judges.

---

## Project Highlights

- **Full-stack SOC dashboard** using React, Express, tRPC, Drizzle, and MySQL.
- **AI-assisted investigations** with configurable hosted or local model providers.
- **Realtime event flow** using server-sent events.
- **Human-in-the-loop response workflow** with self-approval protection.
- **Executive briefing generation** for security leadership.
- **FastMCP forensic agent** for repeatable DFIR workflows.
- **Dockerized MCP service** with hardened runtime settings.
- **Tested TypeScript and Python codebases** using Vitest and pytest.
- **Clean security posture** with secrets removed from source control and explicit secret configuration required.

---

## Repository Layout

This repository contains two main systems:

```text
.
├── sentinel-ops-agent/
│   ├── client/                 # React frontend
│   ├── server/                 # Express backend, tRPC APIs, auth, AI, realtime
│   ├── shared/                 # Shared schemas, types, and database models
│   ├── drizzle/                # Drizzle migration artifacts
│   ├── patches/                # pnpm package patches
│   ├── package.json            # Node scripts and dependencies
│   ├── pnpm-lock.yaml          # Locked Node dependency graph
│   ├── drizzle.config.ts       # Drizzle configuration
│   ├── vite.config.ts          # Vite configuration
│   └── .env.example            # Example web app environment file
│
└── sentinelmcp/
    ├── agent/                  # CLI, investigation loop, evaluator, reporter
    ├── mcp_server/             # FastMCP server and forensic tool handlers
    ├── shared/                 # Shared models, security helpers, utilities
    ├── realtime/               # Realtime support modules
    ├── benchmark/              # Benchmarking and performance artifacts
    ├── docs/                   # API, architecture, security, operations docs
    ├── tests/                  # Python test suite
    ├── docker-compose.yml      # MCP container workflow
    ├── Dockerfile              # MCP service image
    ├── pyproject.toml          # Python package configuration
    └── README.md               # MCP-specific documentation
```

---

## Architecture

```text
+------------------------------------------------------------+
|                         Browser                            |
|        React + Vite + Tailwind SOC Dashboard               |
+-----------------------------+------------------------------+
                              |
                              | tRPC / HTTP
                              v
+------------------------------------------------------------+
|                    Express Backend                         |
|  Auth | Alerts | Incidents | Investigations | AI | SSE      |
+-----------+------------------+------------------+-----------+
            |                  |                  |
            v                  v                  v
+------------------+  +------------------+  +----------------+
|      MySQL       |  | Realtime Events  |  | AI Providers   |
|   Drizzle ORM    |  | Server-Sent Evts |  | Forge/Ollama   |
+------------------+  +------------------+  +----------------+


+------------------------------------------------------------+
|                    Sentinel MCP Agent                      |
|                 Python + FastMCP + Pydantic                |
+-------------+-------------+--------------+-----------------+
              |             |              |
              v             v              v
       +-------------+ +-------------+ +-------------+
       | Disk Tools  | | Memory Tools| | PCAP Tools  |
       +-------------+ +-------------+ +-------------+
              |             |              |
              +-------------+--------------+
                            |
                            v
             +-----------------------------+
             | AI-Assisted DFIR Loop       |
             | Evaluation + Report Output  |
             +-----------------------------+
```

---

## Core Workflows

### Alert Triage

Analysts can review incoming alerts, inspect severity and context, then acknowledge, dismiss, escalate, or move into investigation.

### Incident Investigation

The backend creates investigation jobs, collects relevant context, invokes configured AI analysis, and streams updates back to the dashboard.

### Executive Briefing

Security findings can be converted into leadership-friendly summaries suitable for incident updates, demo presentations, and executive review.

### Realtime Monitoring

The web app uses server-sent events to keep the dashboard updated as alerts, events, and investigation states change.

### MCP Forensic Investigation

The Python MCP agent supports repeatable forensic workflows using validated evidence paths, forensic tool handlers, an AI-assisted investigation loop, deterministic evaluation, and HTML report output.

---

## Tech Stack

| Area | Technologies |
|---|---|
| Frontend | React 19, Vite, TypeScript, Tailwind CSS, Radix UI |
| Backend | Node.js, Express, tRPC, TypeScript |
| Database | MySQL, Drizzle ORM |
| AI Layer | Forge-compatible API, Ollama-compatible local models, Anthropic Claude for MCP workflows |
| MCP / DFIR | Python, FastMCP, Pydantic, YARA-related runtime support |
| Realtime | Server-Sent Events |
| Security | JWT, OAuth integration points, HttpOnly cookies, self-approval guard, path validation |
| Testing | Vitest, pytest, pytest-asyncio, TypeScript compiler checks |
| DevOps | pnpm, Docker, Docker Compose, Python virtual environments |

---

## Installation

### Prerequisites

Install:

- Node.js 20+
- Corepack
- pnpm 10.4.1
- Python 3.10+
- MySQL
- Docker Desktop, optional for MCP container workflow
- Git

---

## Quickstart

### 1. Clone

```bash
git clone <repo-url>
cd <repo>
```

### 2. Start the SOC Web App

```bash
cd sentinel-ops-agent
corepack enable
corepack pnpm install --frozen-lockfile
```

Create a local environment file:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Update `.env` with local secrets and database settings.

Run database migrations:

```bash
corepack pnpm db:push
```

Start the development server:

```bash
corepack pnpm dev
```

The development server runs the backend and serves the frontend experience.

### 3. Seed Demo Data

```bash
corepack pnpm demo:seed
```

### 4. Run Tests

```bash
corepack pnpm check
corepack pnpm test
```

---

## Environment Variables

Use `sentinel-ops-agent/.env.example` as the source of truth for the web app environment file.

| Variable | Required | Used By | Description |
|---|---:|---|---|
| `NODE_ENV` | Yes | Backend | Runtime mode. |
| `PORT` | Yes | Backend | HTTP server port. |
| `DATABASE_URL` | Yes | Backend / Drizzle | MySQL connection string. |
| `JWT_SECRET` | Yes | Auth | Strong secret for JWT signing. |
| `APP_ID` | Yes | Backend auth | Backend application identifier. |
| `VITE_APP_ID` | Yes | Frontend | Frontend application identifier. |
| `OAUTH_SERVER_URL` | Yes | Auth | OAuth server URL. |
| `OAUTH_PORTAL_URL` | Yes | Auth | OAuth portal URL. |
| `VITE_OAUTH_PORTAL_URL` | Yes | Frontend | Browser-facing OAuth portal URL. |
| `OWNER_OPEN_ID` | Yes | Auth | Initial owner identity. |
| `AI_PROVIDER` | Optional | AI | AI provider selection. |
| `LLM_MODEL` | Optional | AI | Hosted model name. |
| `BUILT_IN_FORGE_API_URL` | Optional | AI | Forge-compatible API URL. |
| `BUILT_IN_FORGE_API_KEY` | Optional | AI | Forge-compatible API key. |
| `OLLAMA_BASE_URL` | Optional | AI | Ollama-compatible API base URL. |
| `OLLAMA_MODEL` | Optional | AI | Local model name. |
| `VITE_DEMO_MODE` | Optional | Frontend | Enables demo-oriented UI behavior. |
| `ENABLE_DEMO_EVENT_STREAM` | Optional | Backend | Enables synthetic demo event streaming. |
| `SPLUNK_HEC_URL` | Optional | Integration | Splunk HEC endpoint. |
| `SPLUNK_HEC_TOKEN` | Optional | Integration | Splunk HEC token. |
| `SPLUNK_HOST` | Optional | Integration | Splunk host. |
| `SPLUNK_PORT` | Optional | Integration | Splunk port. |
| `SPLUNK_INDEX` | Optional | Integration | Splunk index. |
| `ANTHROPIC_API_KEY` | Optional | MCP / AI | Anthropic key for Claude-assisted workflows. |

MCP Docker configuration requires an explicit API key:

| Variable | Required | Used By | Description |
|---|---:|---|---|
| `SENTINELMCP_API_KEY` | Yes | MCP service | Required API key for MCP service access. |
| `SENTINELMCP_ALLOWED_PATHS` | Optional | MCP service | Allowed evidence paths. |
| `SENTINELMCP_MAX_ITERATIONS` | Optional | MCP agent | Maximum investigation loop iterations. |
| `SENTINELMCP_LOG_LEVEL` | Optional | MCP service | Logging level. |

Never commit real `.env` files or secrets.

---

## Running the MCP Agent

```bash
cd sentinelmcp
python -m venv .venv
```

Activate the environment.

macOS/Linux:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest tests/ -v
```

Run an example investigation:

```bash
sentinelmcp \
  --disk /evidence/disk.E01 \
  --memory /evidence/mem.dmp \
  --pcap /evidence/capture.pcap \
  --description "Lateral movement investigation" \
  --output report.html
```

Adjust evidence paths to match your local environment and allowed path configuration.

---

## Docker Workflow

The MCP service includes a Docker Compose workflow.

```bash
cd sentinelmcp
```

macOS/Linux:

```bash
export SENTINELMCP_API_KEY="<strong-random-key>"
docker compose up --build
```

Windows PowerShell:

```powershell
$env:SENTINELMCP_API_KEY="<strong-random-key>"
docker compose up --build
```

The Compose configuration mounts local evidence into the container as read-only data and applies hardening controls such as:

- Required API key
- Read-only container filesystem
- `no-new-privileges`
- Temporary `/tmp`
- Read-only evidence mount

---

## Testing

### Web App

```bash
cd sentinel-ops-agent
corepack pnpm check
corepack pnpm test
corepack pnpm build
```

### MCP Agent

```bash
cd sentinelmcp
pytest tests/ -v
```

Optional Python quality checks configured by the project:

```bash
ruff check .
mypy .
```

---

## Security Notes

Security controls implemented in the project include:

- Explicit secret configuration through environment variables.
- Removal of committed local `.env` secrets.
- JWT-based session handling.
- OAuth integration points.
- HttpOnly session cookie behavior.
- Strong JWT secret expectation.
- Self-approval prevention for response actions.
- MCP API key requirement in Docker Compose.
- Evidence path validation in the MCP layer.
- HTML escaping for generated report-style output.
- Docker hardening for the MCP service.

Production review checklist:

- Configure a real OAuth provider.
- Use a managed secret store.
- Disable demo-only behavior outside demo environments.
- Review authorization requirements for multi-user or multi-tenant deployment.
- Validate AI-generated response recommendations before operational execution.

---

## Deployment

### Web Application

```bash
cd sentinel-ops-agent
corepack pnpm install --frozen-lockfile
corepack pnpm db:push
corepack pnpm build
corepack pnpm start
```

Production deployment requires:

- A reachable MySQL database.
- All required environment variables.
- Strong secrets.
- Proper OAuth configuration.
- Network and cookie settings appropriate for the hosting environment.

### MCP Service

```bash
cd sentinelmcp
export SENTINELMCP_API_KEY="<strong-random-key>"
docker compose up --build -d
```

TODO:

- Add hosted demo URL.
- Add cloud-specific deployment guide.
- Add production reverse proxy and TLS guidance.

---

## Hackathon Demo Flow

A strong judging walkthrough:

1. **Open the SOC dashboard**
   - Show alert queue, status, and security operations layout.

2. **Seed demo activity**
   - Run the ransomware demo seed script or enable demo event streaming.

3. **Triage a high-severity alert**
   - Show alert details.
   - Acknowledge or escalate.

4. **Launch AI investigation**
   - Start an investigation job.
   - Show realtime updates and generated analysis.

5. **Review response governance**
   - Demonstrate response action review.
   - Highlight self-approval protection.

6. **Generate executive briefing**
   - Show how technical findings become leadership-ready summaries.

7. **Run MCP forensic workflow**
   - Run the Python MCP agent against sample evidence paths.
   - Generate an HTML investigation report.

8. **Explain architecture**
   - Frontend: React SOC dashboard.
   - Backend: Express/tRPC API.
   - Database: MySQL through Drizzle.
   - AI: configurable model provider layer.
   - MCP: Python FastMCP forensic agent.

---

## Screenshots and GIFs

TODO: Add final demo media.

| Area | Placeholder |
|---|---|
| SOC Dashboard | `docs/screenshots/soc-dashboard.png` |
| Alert Triage | `docs/screenshots/alert-triage.png` |
| AI Investigation | `docs/screenshots/ai-investigation.gif` |
| Executive Briefing | `docs/screenshots/executive-briefing.png` |
| MCP Report | `docs/screenshots/mcp-report.png` |

---

## Future Roadmap

- Add hosted demo deployment.
- Add end-to-end browser tests.
- Expand SIEM integrations.
- Add richer incident timeline visualization.
- Add role-based access control for larger teams.
- Add signed audit logs for response actions.
- Add more production deployment templates.
- Add complete screenshot and demo video assets.
- Expand MCP observability and benchmark dashboards.

---

## Contributors

TODO: Add contributor names, roles, and profile links.

Suggested format:

| Name | Role | Links |
|---|---|---|
| TODO | Project Lead | TODO |
| TODO | Frontend / Backend | TODO |
| TODO | Security / MCP | TODO |

---

## License

This project is licensed under the MIT License.

---

## Acknowledgements

Built with:

- React
- Vite
- TypeScript
- Express
- tRPC
- Drizzle ORM
- MySQL
- Tailwind CSS
- Radix UI
- Vitest
- Python
- FastMCP
- Pydantic
- pytest
- Anthropic Claude
- Ollama-compatible local model workflows
- YARA-related forensic workflows
