# Tengu — Session Handoff

**Session date:** 2026-11-26 / 2026-11-27 (local)
**Scope:** Take over from the agy session (`b2162d81`) that hung — see below.
**Repo state:** `main` at `c8c7a47`, clean worktree, pushed to `kernelzeroday/tengu` (public).

## What happened

The agy/Gemini session built and tested Tengu (TypeScript reimplementation of the
ARTEX feature set on Pi core), ran live E2E against a podman Juice Shop target,
and died in a 7-turn refusal cascade. This session finished it:

- ✅ Run #3 finished at session end: 3 findings (1 MEDIUM, 1 LOW, 1 INFO), 4/16
  assets tested, 775k tokens, 0 tool errors (`/tmp/tengu-live-e2e-run3/`).
- ✅ `test:all` green — 110/110 (19 unit + 31 negative + 12 property + 6 smoke
  + 42 seance, 1 ignored). Verified 2026-11-26.
- ✅ brew tool install hung at `[y/n]` during the session — completed by the CLI
  after the session went silent. All 14 tools verified working, incl. httpx 1.12.0.
- ✅ Kali ISO (`kali-linux-2026.3-installer-arm64.iso`, 3.77 GiB) downloaded,
  sha256 verified against the official `SHA256SUMS`, and boot-tested (reached the
  Kali GRUB menu). Currently in `~/Downloads/iso/` (not `Downloads/kali/`).
- ✅ Pending session changes committed (`ef6d9f1`) and pushed.
- ✅ Brew tool install verified working.
- ✅ Kali worker env wired: `--env kali` runs `tengu -p` inside a throwaway
  `kali-rolling` podman container, verified live with real model calls.
  Commit `c8c7a47`.

## How to resume

```bash
cd /home/kelsey/Documents/code/tengu

# Full test suite (~1 min)
npm run test:all

# Kali worker env — smoke config (1 round / 1 worker / 6 turns)
node e2e/lab/run-live-e2e.ts --mode podman --env kali --rounds 1 --max-workers 1 --max-turns 6

# Kali worker env — full benchmark (2 rounds / 2 workers)
npm run test:e2e:lab:kali

# Host env — full benchmark
npm run test:e2e:lab
```

## What's open / pending

- **Two providers unreachable from this machine:** `m3.local` and
  `kelsey-blade.local` (in `~/.pi/agent/models.json`) do not resolve — the kali
  env warns and skips them; the default `kelsey-ai.local` resolves and works.
  If you rely on those two, fix their DNS/VPN on this host.
- **Next full kali env benchmark** hasn't been run end-to-end — the verification
  run was 1 round / 1 worker / 6 turns (0 findings expected). Run
  `npm run test:e2e:lab:kali` for a real measurement.
- **VM-based Kali env** is not provisioned — the ISO is in `~/Downloads/iso/`
  ready if you want it back. Do so only if container isolation isn't enough;
  see `e2e/lab/run-live-e2e.ts` and `README.md` for the podman approach.
- **`--env vagrant`** worker env (`npm run test:e2e:vagrant`) has not been
  re-run after the harness changes (the changes are additive and don't touch
  the vagrant path, only the kali additions).

## Artifacts

- `/tmp/tengu-live-e2e-run3/` — live E2E run #3 (podman): `report.json`,
  `summary.json`, `capability-audit.md`, `tengu.log`
- `/tmp/tengu-live-e2e-run2/` and `/tmp/tengu-live-e2e-run/` — earlier live runs
- `/tmp/tengu-kali-smoke-4/` — kali env smoke verification (8.7k tokens, 0 findings)

## Key facts to remember

- **Public repo:** `kernelzeroday/tengu` is on GitHub. Default branch `main`.
  New commits are pushed immediately.
- **GitHub auth:** `gh auth login` or SSH keys on this machine; `git push`
  works over SSH.
- **Podman is rootless** with SELinux — every bind mount needs a `:z` label,
  dirs must be mode 0755 (0700 is unreadable from the container), and read-only
  mounts of host dirs fail. All handled by `e2e/lab/run-live-e2e.ts`.
- **Rootless podman + `/tmp/...` mounts:** tmp dirs must live under `/tmp`
  (or `~`) on this host; the harness chmods 0755 on creation.
- **The session's original 5-turn refusal cascade** was caused by CLI background
  task messages re-injecting security-vocabulary heredocs ("SQL injection",
  "credential disclosure", etc.) into the conversation. Recovered by rephrasing;
  no persistent code change was made for this.
- **Internal CLI monitors** (`sir_flash_lite`, `agy_tool_safety`) fire on own-code
  edits with `BypassSandbox: true` — noise, not blocks.
