# Kata Containers

> **⚠️ POC FORK NOTICE — read first**
>
> This is the `shashankbarsin/kata-containers` fork on branch **`poc/dragonball-snapshot`**, used for an **Azure Agent Substrate POC**.
>
> The POC explores adding a **golden-snapshot + diff-apply** snapshot/restore primitive to Dragonball (`src/dragonball/`). Per audit findings, Dragonball today has only partial S/R scaffolding (vCPU pause/resume; a dead `dirty_page_logging` flag) — production S/R was stripped during the early Firecracker fork. We're building it back from scratch as a contribution surface.
>
> **Full design lives in a separate private planning repo: `shashankbarsin/agent-substrate-planning`.**
> Read its `AGENTS.md`, `README.md`, ADRs (`docs/adr/`), and audits (`docs/audits/`) before making non-trivial changes here. Especially relevant:
>
> - ADR-0002 — why Dragonball, honest scope of S/R work
> - ADR-0003 — golden+diff snapshot primitive design; insertion points in `src/dragonball/src/snapshot/`
> - ADR-0006 — latency targets (150 ms p95 target / 300 ms p95 POC-pass)
> - Audit I-002 — current state of Dragonball S/R, gap tiers, recommended module layout
>
> **Hard rules for this fork:**
>
> - **No upstream PRs to `kata-containers/kata-containers` without explicit per-PR user approval.** See planning-repo ADR-0005. Bug reports that don't disclose POC strategy are OK; design contributions are not, until approved.
> - **All POC work goes on `poc/dragonball-snapshot`** (or other `poc/*` branches). `main` tracks upstream cleanly.
> - **All new S/R code lives under `src/dragonball/src/snapshot/`** with minimal wiring edits to the 5 sites named in ADR-0003. This keeps the upstream-PR diff localized.
> - **Userspace virtio-net only.** Vhost-net and vhost-user-net are explicitly out of scope for the POC; their state is opaque or daemon-coordinated and complicates the snapshot story. See planning-repo ADR-0003 §"Network device choice."
> - **Snapshot format is ours.** Not Firecracker's `versionize`/`Persist`, not CLH's format. Bincode with explicit versioning and explicit little-endian.

## Build commands relevant to this work

- Build Dragonball:
  ```
  cd src/dragonball
  cargo build --release
  ```
- Build with feature flags (per audit I-002):
  ```
  cargo build --release --features "virtio-net virtio-blk virtio-vsock"
  ```
- Unit tests (no `/dev/kvm` required for trait/mock tests):
  ```
  cargo test --no-default-features
  ```
- KVM-required integration tests (run on `substrate-poc-1` per planning-repo ADR-0008):
  ```
  cargo test --release --features integration-tests
  ```

## Upstream contribution path (when approved)

When (and only when) the user explicitly approves an upstream PR:
1. Cut a fresh branch off `main` (post-rebase).
2. Cherry-pick only the relevant commits from `poc/*` — exclude this `AGENTS.md` overlay and any other POC-specific bookkeeping.
3. Open the PR to `kata-containers/kata-containers` upstream with a focused scope (one logical change per PR).

## Project Overview (upstream)

For the canonical project description, see the upstream `README.md` and `docs/`. This fork's `poc/dragonball-snapshot` branch does not duplicate upstream documentation.
