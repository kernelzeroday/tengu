# Tengu Roadmap & Feature Coverage Matrix

**Tengu** is a Pi-core (`@earendil-works/pi-*`) autonomous penetration testing platform with a 100% original TypeScript reimplementation of the ARTEX feature set (union of `chu0119-Pojun`, `RuoJi6-ARTEX`, and `Hinln-ARTEX`), paired with a chat-first, session-backed terminal cockpit inspired by `sparkle`, `sd-tui`, `seance`, and `oh-my-pi`.

## Reviewed implementation plan

Baseline: local `chu0119-Pojun` at `42d3eab`, `RuoJi6-ARTEX` at `6997a46`, and `Hinln-ARTEX` at `f3e3f54`. Compare the union of their operator and defensive workflows. Treat shared behavior as one requirement and record fork-specific differences in the same row. Implement in TypeScript through Tengu's existing store and Pi TUI.

`Implemented` means the source and an entry point exist. `Partial` means a named part of the workflow is missing. `Missing` means there is no corresponding end-to-end workflow in the reviewed surface. Mark a row `Verified` after exercising the normal entry point against its acceptance criteria. The original inventory below records earlier project claims. Use this review for the status of items it covers.

| Workflow | Upstream reference | Tengu baseline | Acceptance criteria |
| --- | --- | --- | --- |
| Company and task workspace | All three, `db/company_scope.go`, `db/task_scope.go` | Verified. `/tasks` shows task metadata and distinguishes inherited, included, and excluded scope rules; unlinked sessions clear prior task. | Search tasks and companies, inspect task metadata and scope, and distinguish inherited, included and excluded entries in the TUI. Opening an unlinked session clears the prior task. |
| Asset inventory and graph | All three, `db/assets.go`, `db/task_assets.go` | Verified. Asset DSL filtering, inbound/outbound edges, and same-snapshot coverage are wired and tested. | Filter and page saved assets, inspect inbound and outbound relationships, and show coverage from the same task snapshot as the asset list. |
| Findings triage | All three, `db/findings.go`, `db/finding_assets.go`, `server/findings_groups.go` | Verified. Findings detail, linked evidence, remediation, and recorded verification/retest history are wired and tested. | Search, filter and group by task, asset, severity and status. Open a detail view with linked evidence, remediation, and recorded verification history. |
| Evidence management | All three, `evidence/store.go` | Verified. `inspectArtifact()` distinguishes `readable`, `missing`, and `corrupt` with redacted previews; `exportArtifact()` exports only the selected artifact; `/evidence` in TUI. | Browse task and finding evidence, verify hashes, and distinguish missing, corrupt and readable artifacts. Render a redacted preview and export only the selected artifact. |
| Recorded traffic review | All three, `traffic/evidence.go` | Verified. `maskTrafficRecord()` masks sensitive headers & bodies; `/traffic` view in TUI. | Inspect saved or imported records with sensitive headers masked and export a reviewed selection. |
| Reports and DOCX | All three, `report/report.go` and `report/findings.go`. Pojun adds `report/docx.go` and `server/report_export.go`. | Verified. Added zero-dep OOXML DOCX (`docx.ts`), single-finding exports (`generateFinding` / `generateFindingDocx`), linked retests, consistent redaction, and snapshot-faithful Save in TUI. | Export a task or a selected finding, include linked evidence and recorded verification history, and use consistent redaction in every format. Format changes update the preview, and Save writes that preview's snapshot. |
| Portable task archive | All three, `server/task_archive_package.go`, `db/task_archives_restore.go`, `db/task_archive_aggregate_stats.go` | Verified. Implemented versioned `PortableTaskArchive` (`archive.ts`) with `exportTaskArchive`, `validateTaskArchive` (SHA-256 check), and atomic `restoreTaskArchive` + `tengu archive` CLI. | Export a versioned manifest with selected records and evidence hashes. Preview and validate an archive before restoring it into a separate workspace. A failed import leaves existing records intact. |
| Cost and usage review | Pojun, `server/cost.go` | Verified. `getTaskUsageBreakdown()` breaks down by model, shows unknown cost explicitly (`null`), and `/usage` + `tengu usage` distinguish live estimates from recorded totals. | Distinguish live estimates from recorded totals and break down usage by model where metadata exists. Show unknown cost explicitly. |
| Notification controls | All three, `notify/`. Pojun adds `notify/email.go`. | Verified. Added `previewPayload()` redacted preview and `email` channel support; tested with redaction assertions. | Preview the redacted payload, configure event and severity filters, and show delivery failures using a mock destination in verification. Review network destination validation before adding channels. |
| Vulnerability intelligence review | Existing Tengu cache and feeds | Verified. Local search + `sync-kev`, `sync-nvd`, and `sync-ghsa` feeds. | Search cached advisories, show source and freshness, and display sync failures without losing existing entries. |
| Session browser and resume | Tengu requirement based on `sparkle` and `seance` | Verified. Resumed `Agent` restores saved JSONL turns, per-session drafts/queues stay isolated, unlinked sessions clear prior task, and native `Agent::Tengu` provider added to Seance (41/41 tests pass). | Resume into a mock-model follow-up that refers to an earlier turn. Keep drafts, queued messages and replies attached to their owning session. Add a read-only Seance provider for the existing JSONL format. |
| Fullscreen chat and navigation | Tengu requirement based on `sparkle`, `sd-tui`, `seance`, and `oh-my-pi` | Verified. Chat opens first, multiline composer (`Shift+Enter`/`Ctrl+J`) with per-session drafts, `Ctrl+C`/`Ctrl+D` double-press exit, clickable header/sidebar pills, trackpad wheel routing, and E2E `TuiAltScreen` tests. | Chat opens first. Sessions, assets, findings, evidence and reports are reachable by keyboard and mouse. Keep focus visible and restore it when overlays close. Verify arrows, paging, click targets, wheel routing beneath the pointer, double-press exit, and narrow terminal resize. Add a multiline composer with explicit send and a draft that survives navigation. |
| Live status and approval history | Tengu workspace and intercept store | Verified. Fixed approval modal dismissal-on-open bug (`pendingApprovalResolve` assigned after `openScrollableModal`), added `/approvals` history view, and verified live status displays. | Display persisted decisions and distinguish idle, active, paused, finished and unavailable status. Verify the read-only status displays with fixtures. Do not treat the presence of a modal as evidence that interactive approvals work. |

### Delivery order

1. **Session and terminal reliability.** Restore saved conversation context, verify terminal input in a real terminal and with mock events, and finish the report preview checks. Cover legacy Enter as well as terminals that send enhanced key sequences.
2. **Read-only operator views.** Add task, scope, asset, findings, evidence, and decision-history views with shared search, filtering, keyboard focus, and detail navigation. Use existing store queries before adding new storage APIs. Verify task isolation and empty and error states.
3. **Composer and Seance.** Add multiline editing, draft handling, and read-only session browsing across tools. Verify model streaming, scroll position, and session switching with the composer open.
4. **Reporting and portability.** Complete task and single-finding exports, DOCX, and archive validation and restore. Compare exports against saved fixtures and verify failure recovery before making restore available in the TUI.
5. **Operational polish.** Complete usage breakdowns and notification controls. Evaluate PostgreSQL with concurrent reader and writer cases after the store contract and archive format are stable.

This implementation plan covers defensive and operator workflows. Autonomous offensive workflows and exploit capabilities are outside its scope.

## Original feature inventory and phases

> **Legend:**
> - `Done` — Implemented, wired end-to-end, and covered by automated tests
> - `Partial` — Core engine exists; deeper parity or integration remaining
> - `Planned` — Not yet implemented; scheduled in roadmap phases below

---

## 1. Feature Coverage Matrix (Tengu vs. ARTEX Bases & Local TUI Standards)

### Core Architecture & Runtime
| Feature | ARTEX (`Pojun` / `RuoJi6` / `Hinln`) | Tengu Status | Notes / Location |
| :--- | :--- | :--- | :--- |
| Forked Pi Core (`ai`, `agent`, `tui`, `mcp`, `schema`, `durable`, `codemode`) | Go custom loop (`norma`) | **Done** | `packages/*` (11 forked Pi packages) |
| Pluggable Storage (`TenguStore`) + SQLite Default | PostgreSQL only | **Done** | `packages/tengu-store/src/sqlite-store.ts` (`node:sqlite`, WAL) |
| PostgreSQL `TenguStore` Adapter | PostgreSQL | **Planned** | Phase 3 (drop-in `PostgresTenguStore` implementing `TenguStore`) |
| Pi User Config & Model Auto-Discovery | Web UI LLM config | **Done** | Reads `~/.pi/agent/settings.json`, `models.json`, `auth.json` |
| Multi-Provider LLM Pool, Failover & Refusal Guard | `llmpool/`, `llmguard/` | **Done** | `packages/tengu-engine/src/llm-pool.ts` |
| Token Usage & Cost Accounting | `db/llm_usage.go`, `server/cost.go` | **Done** | Recorded per Planner/Worker/Retester turn + live `tok/s` |
| Persistent Pi-Compatible JSONL Sessions | Task conversations in PG | **Done** | `~/.tengu/sessions/<id>.jsonl` (`tengu --resume`, `Ctrl+S`) |
| Detached Background Daemon (`survives TUI close`) | Always-on Go server | **Done** | `tengu task start/status/pause/stop` (`SIGUSR1`/`SIGTERM`) |
| Headless JSON-RPC 2.0 Server | REST/SSE API | **Done** | `tengu rpc` (`packages/tengu-cli/src/rpc.ts`) |
| Plain-Text Rolling Log File | `logsink.go` | **Done** | `~/.tengu/tengu.log` + `tengu logs` (secret-masked) |

### Dual Graph, Scope & Asset Management
| Feature | ARTEX Base | Tengu Status | Notes / Location |
| :--- | :--- | :--- | :--- |
| Asset Graph (13 asset kinds, edges, neighbors, coverage) | `db/assets.go`, `db/task_assets.go` | **Done** | `packages/tengu-store/src/sqlite-store.ts` |
| Asset DSL (`kind:endpoint tested:false value~admin`) | `db/asset_dsl.go` | **Done** | `packages/tengu-store/src/asset-dsl.ts` |
| Company & Task Scope Guard (Domain, Wildcard, IP, CIDR, Regex, Exclusions) | `db/company_scope.go`, `db/task_scope_guard.go` | **Done** | Enforced inside `InterceptEngine` prior to every tool call |
| Exploration Graph (Begin, Goals, Intents, Facts, Findings, Hints, Lineage) | `db/exploration.go` | **Done** | `derives`, `yields`, `proves`, `blocks`, `requires`, `anchors` |
| DNS Auto-Enrichment (`domain`/`subdomain` → `ip` + `resolves_to`) | `enrich/enrich.go` | **Done** | `packages/tengu-ops/src/enrich.ts` (hooked in `insert_assets`) |
| HTTP Auto-Probe Enrichment on New Sites | `enrich/enrich.go` | **Planned** | Phase 1 |
| ScopeSentry Asset Sync (`RuoJi6-ARTEX`) | `server/sync_scopesentry.go` | **Done** | `packages/tengu-ops/src/scopesentry.ts` + `tengu sync scopesentry` |
| Cross-Task Read-Only Inheritance (`inherited=true`) | `db/exploration_sources.go` | **Planned** | Phase 2 |
| Task Archive Export / Restore Bundles | `server/task_archives.go` | **Planned** | Phase 3 |

### Multi-Agent Engine & 60+ Native Pi Tools
| Feature | ARTEX Base | Tengu Status | Notes / Location |
| :--- | :--- | :--- | :--- |
| Planner / Worker / MainAgent / Retester / SideQuestion | `agent/planner.go`, `worker.go`, `retester.go`, `side_questions.go` | **Done** | `packages/tengu-engine/src/orchestrator.ts` |
| Parallel Workers + Mid-Run `steer_work` & `kill_work` | `agent/worker.go` | **Done** | Native Pi `agent.steer()` & `agent.abort()` |
| Pause / Resume / Stop Execution | `server/task_control.go` | **Done** | Pauses cleanly between tool calls & rounds (`Ctrl+P` / `SIGUSR1`) |
| All 50 ARTEX Domain Tools + `bash` | `agent/tools*.go` | **Done** | `packages/tengu-engine/src/tools.ts` (parallel read / sequential write) |
| Conversational Config & Control Tools (`configure_task`, `configure_intercept_rule`, `start_engagement`, etc.) | Web UI forms | **Done** | 9 additional tools so engagements are configured via natural chat |
| Context Compaction (`transformContext`) | `agent/compaction.go` | **Done** | `packages/tengu-engine/src/compaction.ts` |
| Coverage & Depth Nudges | `server/coverage_nudge.go`, `depth_nudge.go` | **Done** | Injected into Planner rounds when untested assets / unverified findings exist |
| Cold Graph Archiving & Pacing / Low-Novelty Loop Detection | `agent/coldgraph.go`, `idlestop.go`, `pacing.go` | **Planned** | Phase 2 |
| Host-Tool Auto-Discovery (`nmap`, `nuclei`, `ffuf`, `trivy`, etc.) | `hosttools/hosttools.go` | **Done** | `packages/tengu-ops/src/hosttools.ts` (30+ binaries injected into prompts) |
| External MCP Server Integration (`fofa`, Playwright MCP, etc.) | `mcphttp/`, `mcp-servers/` | **Planned** | Phase 1 (wire forked `@earendil-works/pi-mcp` into `TenguToolSet`) |
| Remote Host Execution Daemon (`hostd`) | `hostd/` | **Planned** | Phase 3 |

### Safety & Three-Layer Intercept
| Feature | ARTEX Base | Tengu Status | Notes / Location |
| :--- | :--- | :--- | :--- |
| Layer 1: `hard_deny` (No LLM round-trip) | `db/intercept_builtin_rules.go` | **Done** | Root deletion, disk wipe, fork bomb, host halt |
| Layer 2: `judge` (Live Pi LLM Judge + Timeout Fallback) | `intercept/intercept.go` | **Done** | `createPiLlmJudge()` in `packages/tengu-cli/src/pi-config.ts` |
| Layer 3: `ask` (Interactive TUI Approval Modal) | `server/intercept.go`, `RuoJi6` CallDetail | **Done** | Centered `[Y/Enter] Allow · [N/Esc] Deny` modal in `tui.ts` |
| Static Shell & Python Obfuscation Analyzer | `intercept/shell_static.go`, `python_modules.go` | **Done** | `packages/tengu-intercept/src/static-analyzer.ts` |
| Per-Asset & Per-Task Custom Intercept Rules | `db/asset_intercept.go`, `task_intercept.go` | **Done** | Configurable via `Ctrl+G` modal or `configure_intercept_rule` chat tool |

### Security Operations, Intel, Skills & Reporting
| Feature | ARTEX Base | Tengu Status | Notes / Location |
| :--- | :--- | :--- | :--- |
| HTTP / Auth / Session Login / Diff / API Contract / Probe / JS Audit | `agent/tools_http.go`, `tools_diff.go`, `tools_jsaudit.go` | **Done** | `packages/tengu-ops/src/http-ops.ts` |
| SHA-256 Content-Addressed Evidence Store + Integrity Check | `evidence/store.go` | **Done** | `packages/tengu-ops/src/evidence.ts` |
| OOB Callback Listener (HTTP & TCP) | `listener/listener.go` | **Done** | `packages/tengu-ops/src/listener.ts` |
| Background Jobs & PoC Script Workspace | `agent/tools_jobs.go`, `tools_script.go` | **Done** | `packages/tengu-ops/src/jobs.ts` |
| HTTP Recording Proxy + HAR 1.2 Export | `traffic/traffic.go`, `archive.go` | **Partial** | `traffic-proxy.ts` built; auto-injecting `HTTP_PROXY` + TLS MITM CA planned (Phase 1) |
| Vuln Intel (Local Cache + CISA KEV + NVD + GHSA + Nuclei) | `vulnintel/` | **Done** | `packages/tengu-ops/src/vuln-intel.ts` + `tengu vuln sync-kev/sync-nvd/sync-ghsa` |
| 23 Built-in Security Skills + `load_skill` Dynamic Injection | `skills/*` (23 skills + reference playbooks) | **Partial** | All 23 skills + `load_skill` wired; expanding deep per-vuln reference playbooks & helper scripts in Phase 1 |
| Multi-Channel Notifications (Webhook, Telegram, DingTalk, Feishu, WeCom) | `notify/` | **Done** | `packages/tengu-ops/src/notify.ts` (severity-filtered + secret-masked) |
| Reports: Markdown, JSON, SARIF 2.1.0, HTML | `report/` | **Done** | `packages/tengu-ops/src/report.ts` + rendered TUI preview (`Ctrl+R`) |
| Reports: DOCX Export | `report/docx*.go` | **Planned** | Phase 3 |
| Outbound Proxy Pool & Health Probes | `proxyprobe/`, `server/proxypool_*.go` | **Planned** | Phase 3 |
| Cron Scheduler & Webhook Triggers | `server/scheduler.go`, `triggers.go` | **Planned** | Phase 3 |

### Terminal UX (`sparkle` / `sd-tui` / `seance` Standards)
| Feature | Reference Standard | Tengu Status | Notes / Location |
| :--- | :--- | :--- | :--- |
| Chat-First Fullscreen Cockpit + Toggleable Mission Sidebar | `sparkle` / `oh-my-pi` | **Done** | `TenguCockpitApp` (`Ctrl+B` sidebar, `Tab` Live/Graph/Findings) |
| Live Streaming Chat (Prefill Spinner, Thinking Block, Inline Tool Pills, Streaming Markdown, `tok/s`) | `sparkle` | **Done** | `packages/tengu-cli/src/chat-stream.ts` (`Ctrl+T` toggle thinking) |
| `Ctrl+C` / `Ctrl+D` Double-Press Exit, `Esc` Abort/Clear, `Ctrl+U` Clear | `sparkle` / `sd-tui` | **Done** | `packages/tengu-cli/src/tui.ts` |
| Message Queuing While Streaming (`Enter` queues, `↑` pops to edit) | `sparkle` | **Done** | Auto-drains after current turn finishes |
| Slash-Command `Tab` Completion & Cross-Session Prompt History | `sparkle` / `sd-tui` | **Done** | `~/.tengu/history.json` |
| Trackpad/Mouse Wheel Focus-Follows-Mouse + Clickable Pills + `┃` Scrollbars | `seance` / `sparkle` | **Done** | `TuiAltScreen` `setLayoutRoot` + `handleMouse` |
| Multi-Line Composer (`Shift+Enter` / `Ctrl+J`) & `/attach` File Context | `sparkle` | **Planned** | Phase 1 |
| Native `tengu` Session Provider in `seance` | `seance` | **Planned** | Phase 1 |
| Text Selection / Click-to-Copy & Inline Finding Cards in Chat | `sparkle` / `seance` | **Planned** | Phase 2 |

---

## 2. Phased Roadmap

### Phase 1 — Operator Craft & Deep Pentest Parity (Next)
- **Deepen the 23 Skill Playbooks**: Expand each built-in skill with full structured vulnerability-class checklists (IDOR/BOLA, SSRF, OAuth/JWT, SQLi, XSS, Race Conditions, WAF Bypass, Cloud IMDS, AD, APK/Frida) and reusable PoC helper scripts under `skills/`.
- **Wire `@earendil-works/pi-mcp` into `TenguToolSet`**: Load user-configured MCP servers (`~/.tengu/mcp.json`, e.g., Playwright MCP, FOFA, Shodan) directly into Planner/Worker/Chat tools.
- **Auto-MITM Recording Proxy**: Option to auto-start `TrafficRecorderProxy` with a local self-signed CA and inject `HTTP_PROXY`/`HTTPS_PROXY` into worker `bash` and `http_request` calls.
- **`seance` Integration**: Add a native `tengu` session reader to `~/Documents/code/seance` (reading `~/.tengu/sessions/*.jsonl` + `~/.tengu/tengu.db`) for live cross-agent session search and preview.
- **Multi-Line Prompt Composer & `/attach`**: Upgrade the prompt bar from single-line `Input` to Pi's multi-line `Editor` (`Shift+Enter` / `Ctrl+J` newline, `/attach <path>` with path tab-completion).

### Phase 2 — Long-Running Autonomy & Verification Depth
- **Cold Graph & Anti-Loop Pacing**: Implement ARTEX's `coldgraph` summarization, low-novelty fact detection, and idle-stop / lease timeouts for multi-hour autonomous runs.
- **Cross-Task Knowledge Inheritance**: Allow child tasks (`parentTaskId`) to inherit read-only facts, findings, and asset scope from prior engagements (`inherited=true`).
- **Interactive Finding & Trace Inspector in Sidebar**: Click any finding or active worker in the Mission Sidebar to pop open its live trace or rendered Markdown report, plus one-key Retest (`retestFinding`).
- **Context Compaction Command (`/compact`)**: Manual and automatic conversation compaction with inline collapsible summary dividers (`Ctrl+O`), matching `sparkle`.

### Phase 3 — Scale, Storage & Enterprise Polish
- **PostgreSQL `TenguStore` Adapter**: Optional Postgres backend (`TENGU_PG_DSN`) implementing the exact `TenguStore` interface for multi-operator / team deployments.
- **Task Archive Bundles**: Export/import complete portable task archives (DB records + SHA-256 evidence artifacts + HAR traffic + session JSONL).
- **DOCX Report Exporter**: Native `.docx` pentest report generation alongside Markdown, JSON, SARIF 2.1.0, and HTML.
- **Outbound Proxy Pool & Scheduled Triggers**: Rotating SOCKS5/HTTP proxy pool with health checks, plus cron/webhook recurring scan triggers.
- **Remote Execution Agent (`hostd`)**: Optional lightweight remote runner for executing tools inside isolated target-network jump hosts.
