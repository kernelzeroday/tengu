# Tengu

**Tengu** is an AI autonomous penetration testing platform rebuilt from the ground up on a forked **Pi core** (`@earendil-works/pi-*`), with a 100% original TypeScript reimplementation of the full ARTEX feature set (union of `chu0119-Pojun`, `RuoJi6-ARTEX`, and `Hinln-ARTEX`).

> **Authorized Testing Only**: Use Tengu exclusively on systems and networks where you have explicit written authorization.

## Architecture

```
packages/
  ├── telemetry, schema, chord, tui, codemode, mcp, ai, durable, env, agent, coding-agent   # Forked Pi core
  ├── tengu-store       # Pluggable TenguStore interface + zero-config node:sqlite backend, Dual Graph, Asset DSL, Scope Guard
  ├── tengu-intercept   # Three-layer Intercept Engine (hard_deny / judge / ask), static shell/python analyzer, approval audit log
  ├── tengu-ops         # Evidence Store (SHA-256), HTTP/Auth/Diff/Contract/Probe/JS-Audit, Traffic Proxy, OOB Listener, Jobs, VulnIntel, ScopeSentry Sync, Notifications, Reports (MD/JSON/SARIF/HTML)
  ├── tengu-engine      # Planner/Worker/MainAgent/Retester orchestrator on Pi Agent, 53 native AgentTools, LLM Pool & Failover, 23 built-in pentest skills
  └── tengu-cli         # Pi TUI interactive console + headless CLI & JSON-RPC 2.0 stdio server
```

## Quick Start

```bash
npm install
npm run build
npm run test:tengu

# Launch interactive Pi TUI
npm run tengu

# Headless CLI & JSON-RPC
node packages/tengu-cli/dist/cli.js --help
node packages/tengu-cli/dist/cli.js task create "Q4 API Pentest"
node packages/tengu-cli/dist/cli.js rpc
```
