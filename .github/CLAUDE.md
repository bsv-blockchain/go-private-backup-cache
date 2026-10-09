# CLAUDE.md

## 📦 Project Summary

**go-private-backup-cache** is an append-only, zero-knowledge HTTP service that stores encrypted wallet-backup blobs for BSV wallets. A wallet cannot be restored from its seed alone — spending needs derivation metadata that only lives in the wallet's local database — so wallets push that database here as encrypted delta chunks, and a reinstalled wallet replays them. Recovery then needs **only** the recovery phrase, not the lost device.

### Core Capabilities
- **Zero-Knowledge Storage**: Blobs are encrypted client-side with a seed-derived key; the server has no decrypt path and never will
- **Stateless Authentication**: One signed `X-Bsv-Auth` proof per request (`@bsv/auth`-compatible), verified before the body is read — no handshake, no session
- **Pseudonymous Accounts**: The account is whatever key signed the proof; there is no identity parameter anywhere in the API
- **Streaming Blobs**: Uploads and downloads stream through a fixed chunk buffer, up to a 200 MiB cap, so memory never scales with blob size
- **Generational Retention**: Client-driven compaction keeps the current and previous generation; account erasure on request (GDPR Art. 17)
- **Operations**: PostgreSQL or in-memory store, horizontally scalable replicas, optional OTLP traces and metrics

### Repository Layout
- `cmd/server` – service entrypoint; `internal/` – server packages (auth proofs, blob store, nonce store, handlers, telemetry)
- `client/` – Go client; `ts-client/` – TypeScript client (`@bsv/backup-cache-client`); `test-client/` – cross-language interop suite
- `docs/authproof-protocol.md` – the authentication protocol specification

### Non-Negotiables
Never add a decrypt path, an identity parameter, or a payment flow (402) to this service, and never put raw paths, pseudonyms or device IDs into telemetry labels. Each one breaks the zero-knowledge property the service exists to provide.

## 🤖 Welcome, Claude

This repository uses **`AGENTS.md`** as the single source of truth for:

* Coding conventions (naming, formatting, commenting, testing)
* Contribution workflows (branch prefixes, commit message style, PR templates)
* Release, CI, and dependency‑management policies
* Security reporting and governance links

> **TL;DR:** **Read `AGENTS.md` first.**
> All technical or procedural questions are answered there.

### Quick Checklist for Claude

1. **Study `AGENTS.md`**
   Make sure every automated change or suggestion respects those rules.
2. **Follow branch‑prefix and commit‑message standards**
   They drive Mergify auto‑labeling and CI gates.
3. **Never tag releases**
4. **Pass CI**
   Run `go fmt`, `goimports`, `go vet`, `staticcheck`, and `golangci‑lint` locally before opening a PR.

If you encounter conflicting guidance elsewhere, `AGENTS.md` wins.
Questions or ambiguities? Open a discussion or ping a maintainer instead of guessing.

Happy hacking!
