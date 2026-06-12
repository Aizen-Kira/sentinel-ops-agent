# Sentinel Ops Agent

React, Express, tRPC, and Drizzle dashboard for SOC alert triage, incident correlation, executive briefings, investigation jobs, and local/demo security operations workflows.

## Common Commands

```bash
corepack pnpm check
corepack pnpm test
corepack pnpm build
```

## Demo Mode

Set `VITE_DEMO_MODE=true` to show UI disclaimers around mocked, seeded, simulated, or fallback behavior. Development mode shows these notices by default unless `VITE_DEMO_MODE=false` is set. Production builds hide them unless explicitly enabled.

`ENABLE_DEMO_EVENT_STREAM=true` starts the synthetic event stream on the server.

## Known Limitations

### HTML Escaping

- Fixed: `server/lib/briefing/briefingService.ts` now escapes dynamic briefing fields before rendering exported HTML email.
- Fixed: the chart style helper no longer uses `dangerouslySetInnerHTML`; generated CSS is rendered as text and unsafe CSS variable names or values are filtered.
- Residual edge case: any future server-rendered HTML string or React `dangerouslySetInnerHTML` usage must call `escapeHtml()` from `shared/html.ts` or avoid raw HTML entirely. React text nodes are considered safe by default.

### Demo Mode Features

- Alert feed can be populated by generated connector events or the ransomware seed script.
- Executive brief can fall back to a rule-based/heuristic summary when no live AI provider is configured.
- Investigation analysis can run in Local Analyst Mode or deterministic playbook fallback instead of a live cloud LLM.
- CISO briefing generation can return mock content when `ANTHROPIC_API_KEY` is absent or the LLM call fails.
- Response recommendations can use hardcoded enrichment inputs when live incident enrichment is not supplied.
- Splunk HEC/search clients run in mock mode when Splunk environment variables are missing.
- Metrics can be zero-filled or derived from demo data when no metric snapshots are present.
- Query Tool performs local alert-store filtering; it is SPL-style, not a full SPL parser.

### Other Constraints

- A MySQL-compatible `DATABASE_URL` is required outside tests.
- Production startup requires strong `JWT_SECRET`, app ID, OAuth URLs, and valid AI-provider settings.
- Tenant isolation is currently a placeholder: all users resolve to the default tenant.
- The default `user` role currently has alert-management capability; review before broad production signup.
- There is no dedicated lint script in `package.json`; use `corepack pnpm check` and `corepack pnpm test` as the current validation gates.
