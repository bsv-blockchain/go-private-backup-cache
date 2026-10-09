<div align="center">

# 🔐&nbsp;&nbsp;go-private-backup-cache

**Zero-knowledge, append-only cache for encrypted BSV wallet backups.**

<br/>

<a href="https://github.com/bsv-blockchain/go-private-backup-cache/releases"><img src="https://img.shields.io/github/release-pre/bsv-blockchain/go-private-backup-cache?include_prereleases&style=flat-square&logo=github&color=black" alt="Release"></a>
<a href="https://golang.org/"><img src="https://img.shields.io/github/go-mod/go-version/bsv-blockchain/go-private-backup-cache?style=flat-square&logo=go&color=00ADD8" alt="Go Version"></a>
<a href="https://github.com/bsv-blockchain/go-private-backup-cache/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-OpenBSV-blue?style=flat-square" alt="License"></a>

<br/>

<table align="center" border="0">
  <tr>
    <td align="right">
       <code>CI / CD</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://github.com/bsv-blockchain/go-private-backup-cache/actions"><img src="https://img.shields.io/github/actions/workflow/status/bsv-blockchain/go-private-backup-cache/fortress.yml?branch=main&label=build&logo=github&style=flat-square" alt="Build"></a>
       <a href="https://github.com/bsv-blockchain/go-private-backup-cache/actions/workflows/ts.yml"><img src="https://img.shields.io/github/actions/workflow/status/bsv-blockchain/go-private-backup-cache/ts.yml?branch=main&label=interop&logo=typescript&logoColor=white&style=flat-square" alt="Interop"></a>
       <a href="https://github.com/bsv-blockchain/go-private-backup-cache/actions"><img src="https://img.shields.io/github/last-commit/bsv-blockchain/go-private-backup-cache?style=flat-square&logo=git&logoColor=white&label=last%20update" alt="Last Commit"></a>
    </td>
    <td align="right">
       &nbsp;&nbsp;&nbsp;&nbsp; <code>Quality</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://codecov.io/gh/bsv-blockchain/go-private-backup-cache"><img src="https://codecov.io/gh/bsv-blockchain/go-private-backup-cache/branch/main/graph/badge.svg?style=flat-square" alt="Coverage"></a>
    </td>
  </tr>

  <tr>
    <td align="right">
       <code>Security</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://scorecard.dev/viewer/?uri=github.com/bsv-blockchain/go-private-backup-cache"><img src="https://api.scorecard.dev/projects/github.com/bsv-blockchain/go-private-backup-cache/badge?style=flat-square" alt="Scorecard"></a>
       <a href=".github/SECURITY.md"><img src="https://img.shields.io/badge/policy-active-success?style=flat-square&logo=security&logoColor=white" alt="Security"></a>
    </td>
    <td align="right">
       &nbsp;&nbsp;&nbsp;&nbsp; <code>Community</code> &nbsp;&nbsp;
    </td>
    <td align="left">
       <a href="https://github.com/bsv-blockchain/go-private-backup-cache/graphs/contributors"><img src="https://img.shields.io/github/contributors/bsv-blockchain/go-private-backup-cache?style=flat-square&color=orange" alt="Contributors"></a>
       <a href="https://deepwiki.com/bsv-blockchain/go-private-backup-cache"><img src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
    </td>
  </tr>
</table>

</div>

<br/>
<br/>

<div align="center">

### <code>Project Navigation</code>

</div>

<table align="center">
  <tr>
    <td align="center" width="33%">
       📦&nbsp;<a href="#-installation"><code>Installation</code></a>
    </td>
    <td align="center" width="33%">
       🧪&nbsp;<a href="#-examples--tests"><code>Examples&nbsp;&&nbsp;Tests</code></a>
    </td>
    <td align="center" width="33%">
       📚&nbsp;<a href="#-documentation"><code>Documentation</code></a>
    </td>
  </tr>
  <tr>
    <td align="center">
       🤝&nbsp;<a href="#-contributing"><code>Contributing</code></a>
    </td>
    <td align="center">
       🛠️&nbsp;<a href="#-code-standards"><code>Code&nbsp;Standards</code></a>
    </td>
    <td align="center">
       🔌&nbsp;<a href="#-api"><code>API</code></a>
    </td>
  </tr>
  <tr>
    <td align="center">
       🤖&nbsp;<a href="#-ai-usage--assistant-guidelines"><code>AI&nbsp;Usage</code></a>
    </td>
    <td align="center">
       ⚖️&nbsp;<a href="#-license"><code>License</code></a>
    </td>
    <td align="center">
       👥&nbsp;<a href="#-maintainers"><code>Maintainers</code></a>
    </td>
  </tr>
</table>
<br/>

## 📖 Overview

**go-private-backup-cache** is an append-only, zero-knowledge cache for encrypted wallet-backup blobs.

A BSV wallet cannot be recovered from its seed alone. Spending an output requires derivation
metadata that exists only in the wallet's local database — change outputs carry a random
derivation suffix, and received BRC-29 outputs carry a `derivationPrefix`, `derivationSuffix`
and `senderIdentityKey` chosen by the sender. None of it is on-chain, and there is no rescan
path. A user who dutifully wrote down their recovery phrase and then lost their phone still
cannot spend their coins.

This service holds the other half. Wallets push their database to it as encrypted delta
chunks; a reinstalled wallet replays them and is whole again. It turns recovery from
"you need **both** the phrase and the device" into "you need **only** the phrase".

### Core Capabilities
- **Zero-Knowledge Storage**: Blobs are encrypted client-side under a seed-derived key; the server has no decrypt path
- **Stateless Authentication**: One signed `X-Bsv-Auth` proof per request, verified before the body is read — no handshake, no session
- **Pseudonymous Accounts**: The account is the key that signed the proof; there is no identity parameter anywhere in the API
- **Streaming Blobs**: Uploads and downloads stream through a bounded buffer, up to a 200 MiB cap per blob
- **Generational Retention**: Client-driven compaction, two generations kept, account erasure on request (GDPR Art. 17)
- **Production Operations**: PostgreSQL storage, freely scalable replicas, optional OTLP traces and metrics

### What's in the Box
- **[`cmd/server`](cmd/server)** – the HTTP service, also published as a container image
- **[`client/`](client)** – Go client that speaks the whole protocol
- **[`ts-client/`](ts-client)** – TypeScript client, published as [`@bsv/backup-cache-client`](https://www.npmjs.com/package/@bsv/backup-cache-client)
- **[`test-client/`](test-client)** – interop suite that drives the Go server with the real TypeScript client

<br/>

## 🔒 Privacy Model

It cannot read a single byte of what it stores, and this is structural rather than a promise.

- **Blobs are encrypted before they arrive**, with a key derived from the client's wallet
  seed using counterparty `self`. Nobody but that seed holder can derive it. There is no
  decrypt path in this codebase and there must never be one.
- **The account address is a pseudonym.** Clients authenticate with a per-request signed
  proof (see [docs/authproof-protocol.md](docs/authproof-protocol.md)) under a key derived
  from their wallet seed, not their wallet identity key. The server stores blobs under
  whatever key authenticated, so it never learns the on-chain identity.
- **There is no identity parameter anywhere in the API.** The account is taken from the
  verified proof and nothing else. A client cannot name another account to read or
  write, because there is no field in which to name one.

### What it does still observe

Being honest about the residual matters more than the claim.

The server sees source IP, TLS fingerprint, request cadence, ciphertext sizes, device count
and total volume. Because one pseudonym spans a user's devices — restore has to be able to
enumerate them — it also learns that those devices belong to one person. **IP is the real
residual and it is not small**: a phone's address is geolocatable, ISP-attributable and often
stable enough within a session to individuate.

So this is not unlinkability. What it is: the correlation requires an operator to
deliberately retain and cross-reference logs they have no business reason to keep, it
degrades under CGNAT, VPNs and roaming, and it leaves behind no artifact that survives a
breach or a subpoena. It is a policy failure rather than an architectural fact.

<details>
<summary><strong><code>Why the service is free, permanently</code></strong></summary>
<br/>

Charging was evaluated properly — go-402-pay (BRC-121) with a BRC-228 ephemeral
`senderIdentityKey`, on the theory that an unlinked payment identity preserves the property.
**It does not.** BRC-228 removes the least important leak.

The pseudonymous client wallet has no UTXOs, so the user's *real* wallet must fund any
payment. That hands over:

- **The BEEF, which is the actual leak.** `x-bsv-beef` carries each input's ancestry back to
  a proof — meaning one or more complete prior transactions of the user's wallet, as bytes,
  not references. Delivered inside a request the auth proof has already bound to the
  pseudonym, it is a signed assertion that this pseudonym controls those outpoints.
- **A chain the operator can walk.** Payment *n*'s change funds payment *n+1*, so two
  payments are enough to follow the wallet forward with any public indexer. Change amounts
  additionally disclose balance and its trajectory.
- **A join that needs no chain analysis at all.** Wallets already send their real identity
  key in cleartext to ordinary BRC-121 merchants and auth peers by construction. One join
  against any service holding both that key and an outpoint is enough.
- **Records this service would otherwise never hold.** Replay protection in go-402-pay is
  delegated to the wallet's `InternalizeAction`, so a paid deployment needs a funded,
  storage-backed wallet and gains a permanent per-payment ledger keyed by pseudonym. Today it
  holds one crypto-only key and opaque bytes.

Today's residual is correlational and deniable. Payment would replace it with something
cryptographic, durable, self-documenting and — once accounting obligations attach —
mandatorily retained. If revenue is ever needed: charge elsewhere, in a relationship where
the user is already identified; or, if the real goal is abuse control, use per-pseudonym
quotas, which leak nothing.

**Do not add a 402 to this service and describe the result as private.**

</details>

<br/>

## 📦 Installation

**go-private-backup-cache** requires a [supported release of Go](https://golang.org/doc/devel/release.html#policy).

### Run the server

From source:

```bash
cp .env.example .env
# set SERVER_PRIVATE_KEY to 64 hex characters
go run ./cmd/server
```

Or from the published container image:

```bash
docker run --rm -p 8080:8080 \
  -e SERVER_PRIVATE_KEY="$(openssl rand -hex 32)" \
  -e DATABASE_URL="postgres://user:pass@host:5432/backup_cache?sslmode=require" \
  ghcr.io/bsv-blockchain/go-private-backup-cache:latest
```

Without `DATABASE_URL` the service runs on an in-memory store and logs a warning. That is for
development only — everything is lost on restart, which for a backup service is a bad
surprise.

### Configuration

| Variable                      | Default     | Description                                                                 |
|-------------------------------|-------------|-----------------------------------------------------------------------------|
| `SERVER_PRIVATE_KEY`          | –           | **Required.** 64 hex characters; the server's identity key (holds no funds) |
| `DATABASE_URL`                | –           | PostgreSQL DSN. Unset means the in-memory store (development only)          |
| `PORT`                        | `8080`      | HTTP listen port                                                            |
| `MAX_BLOB_BYTES`              | `209715200` | Per-blob cap (200 MiB), published at `GET /v1/limits`                       |
| `LOG_LEVEL`                   | `info`      | `debug`, `info`, `warn` or `error`                                          |
| `LOG_FORMAT`                  | `json`      | `json` or `text`                                                            |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | –           | OTLP/HTTP collector base URL. Unset means telemetry export is off           |

### Use a client

Go:

```shell script
go get -u github.com/bsv-blockchain/go-private-backup-cache/client
```

```go
c := client.New("https://backup.example.com", pseudonymKey)
res, err := c.AppendBytes(ctx, deviceID, generation, seq, prevSha256, ciphertext)
```

TypeScript:

```bash
npm install @bsv/backup-cache-client @bsv/sdk
```

See the [TypeScript client README](ts-client/README.md) for usage. Both clients encrypt nothing on your behalf — **encrypt before you append**.

<br/>

## 🔌 API

Everything except `/health` and `/v1/limits` requires an `X-Bsv-Auth` proof header —
one signed proof per request, verified before the body is read, no handshake and no
session. The scheme is `@bsv/auth`-compatible and specified in
[docs/authproof-protocol.md](docs/authproof-protocol.md).
`{deviceId}` is a client-generated opaque `[a-f0-9]{32}`. Sequences are 1-based and
contiguous within a `(pseudonym, deviceId, generation)`.

| Method   | Path                                              | Notes                                                                  |
|----------|---------------------------------------------------|------------------------------------------------------------------------|
| `GET`    | `/health`                                         | Unauthenticated                                                        |
| `GET`    | `/v1/limits`                                      | Unauthenticated; `maxBlobBytes`, `maxBodyBytes`, `serverIdentityKey`   |
| `GET`    | `/v1/manifest`                                    | Devices and generations for the caller                                 |
| `POST`   | `/v1/log/{deviceId}?seq=&generation=&prevSha256=` | Raw `application/octet-stream` body, streamed                          |
| `GET`    | `/v1/log/{deviceId}?generation=&from=&limit=`     | Entry metadata                                                         |
| `GET`    | `/v1/log/{deviceId}/{seq}?generation=`            | Raw ciphertext, streamed, `Content-Length` set                         |
| `DELETE` | `/v1/generation/{deviceId}/{generation}`          | Prune an old generation                                                |
| `DELETE` | `/v1/account`                                     | Erase every generation for the caller (GDPR Art. 17)                   |

Uploads are raw binary, not base64 — the body on the wire is the blob, byte for byte, and
its sha256 is bound into the auth proof. Both directions stream: a blob is never resident
in server memory.

Errors use `{"status":"error","code":"ERR_...","description":"..."}`.

### Retention

The current and previous generation are kept — two, so a compaction that fails partway never
leaves a user with zero recoverable backups. Compaction is client-driven: write a full
snapshot as generation N+1, then delete N-2.

**There is no time-based expiry.** A pseudonym untouched for years belongs to precisely the
user this service exists for: someone who lost their device and has not yet replaced it.

<br/>

## 📚 Documentation

- **Protocol** – The auth-proof scheme, signing rules and test vectors in [docs/authproof-protocol.md](docs/authproof-protocol.md)
- **Go Client Reference** – Dive into the godocs at [pkg.go.dev/github.com/bsv-blockchain/go-private-backup-cache/client](https://pkg.go.dev/github.com/bsv-blockchain/go-private-backup-cache/client)
- **TypeScript Client** – Install and usage in the [ts-client README](ts-client/README.md)
- **Interop Suite** – How the cross-language check works in the [test-client README](test-client/README.md)
- **Test Suite** – Unit, security and end-to-end tests live beside the code (powered by [`testify`](https://github.com/stretchr/testify))

<br/>

<details>
<summary><strong><code>Operational Notes</code></strong></summary>
<br/>

- **Replicas scale freely.** Authentication is stateless per request; the only shared
  state is the nonce table in Postgres, where an `INSERT ... ON CONFLICT` makes replay
  refusal atomic across replicas. There is no handshake, no session and no sticky routing.
- **Blobs are capped at 200 MiB** (`MAX_BLOB_BYTES`) so a 100 MB transaction fits with
  room for any honest encoding overhead. The cap is a policy number, not a memory number:
  the body streams through a 1 MiB chunk buffer into `blob_chunks` rows, and downloads
  stream back out the same way, so server memory use does not scale with blob size.
- **Anything between client and server must allow the cap through.** A proxy or CDN with
  its own body limit answers before this service does — Cloudflare's proxy, for one, caps
  uploads at 100 MB on non-enterprise plans.
- **A whole request must finish inside 30 minutes** (`server.StreamTimeout`, read and
  write). Generous enough for the full cap on a slow honest link; what it bounds is the
  deliberately-slow stream, because an upload holds a store transaction — and with it a
  pooled database connection — for as long as its body keeps trickling, and the nonce
  store every authentication needs shares that pool.
- **Oversize uploads answer 413 before authentication.** The size guard sits ahead of the
  auth layer and overrides it, so a size problem is never reported as an auth problem.
  Clients should branch on the status or on `ERR_BLOB_TOO_LARGE`, never on message text.
- **The cap and the server's identity key are published at `GET /v1/limits`**,
  unauthenticated: the cap so a client can read it instead of carrying a copy that drifts
  out of sync, the key because a client cannot build its first proof without it. Neither
  is a secret and knowing them grants no capability.
- **A schema wipe ships with this version.** The first migration drops the pre-streaming
  `blob_log` table (single `bytea` column) if that is what it finds, per the standing
  no-backward-compatibility decision. Deploying it erases stored blobs from older versions.
- **The server wallet holds no funds.** `CompletedProtoWallet` is key-only: it cannot spend,
  so it cannot be drained.
- **Telemetry is OTLP and off by default.** Set `OTEL_EXPORTER_OTLP_ENDPOINT` to a
  collector's base URL and the service exports traces (one span per request plus store
  operations) and metrics (`http.server.request.duration` histogram,
  `http.server.errors` counter) over OTLP/HTTP. Every request also gets one summary log
  line — route, status, duration, bytes — at WARN for 5xx, with `trace_id` stamped on
  every log line written inside a traced request. Span names and metric labels use route
  patterns (`POST /v1/log/{deviceId}`), never raw paths: raw paths would explode metric
  cardinality and hand pseudonyms and device IDs to the telemetry backend, which sits
  outside this service's zero-knowledge boundary. `/health` is untraced so probes do not
  drown real traffic.

</details>

<details>
<summary><strong><code>Development Build Commands</code></strong></summary>
<br/>

Get the [MAGE-X](https://github.com/mrz1836/mage-x) build tool for development:
```shell script
go install github.com/mrz1836/mage-x/cmd/magex@latest
```

View all build commands

```bash script
magex help
```

</details>

<details>
<summary><strong>Repository Features</strong></summary>
<br/>

This repository includes 25+ built-in features covering CI/CD, security, code quality, developer experience, and community tooling.

**[View the full Repository Features list →](.github/docs/repository-features.md)**

</details>

<details>
<summary><strong><code>Releases & Container Images</code></strong></summary>
<br/>

This project uses [goreleaser](https://github.com/goreleaser/goreleaser) for streamlined GitHub releases. To get started, install it via:

```bash
brew install goreleaser
```

The release process is defined in the [.goreleaser.yml](.goreleaser.yml) configuration file.

Then create and push a new Git tag using:

```bash
magex version:bump push=true bump=patch branch=main
```

Every release tag also publishes a matching container image (`ghcr.io/bsv-blockchain/go-private-backup-cache:vX.Y.Z`) via the [Docker Publish](.github/workflows/docker-publish.yml) workflow; every push to `main` refreshes `latest` and a commit-SHA tag.

This process ensures consistent, repeatable releases with properly versioned artifacts and citation metadata.

</details>

<details>
<summary><strong><code>Pre-commit Hooks</code></strong></summary>
<br/>

Set up the Go-Pre-commit System to run the same formatting, linting, and tests defined in [AGENTS.md](.github/AGENTS.md) before every commit:

```bash
go install github.com/mrz1836/go-pre-commit/cmd/go-pre-commit@latest
go-pre-commit install
```

The system is configured via modular environment files in [`.github/env/`](.github/env/README.md) and provides 17x faster execution than traditional Python-based pre-commit hooks. See the [complete documentation](http://github.com/mrz1836/go-pre-commit) for details.

</details>

<details>
<summary><strong>GitHub Workflows</strong></summary>
<br/>

All workflows are driven by modular configuration in [`.github/env/`](.github/env/README.md) — no YAML editing required.

**[View all workflows and the control center →](.github/docs/workflows.md)**

</details>

<details>
<summary><strong><code>Updating Dependencies</code></strong></summary>
<br/>

To update all dependencies (Go modules, linters, and related tools), run:

```bash
magex deps:update
```

This command ensures all dependencies are brought up to date in a single step, including Go modules and any tools managed by [MAGE-X](https://github.com/mrz1836/mage-x). It is the recommended way to keep your development environment and CI in sync with the latest versions.

npm dependencies for [`ts-client/`](ts-client) and [`test-client/`](test-client) are kept current by [Dependabot](.github/dependabot.yml).

</details>

<br/>

## 🧪 Examples & Tests

All unit tests run via [GitHub Actions](https://github.com/bsv-blockchain/go-private-backup-cache/actions) and use [Go version 1.26.x](https://go.dev/doc/go1.26). View the [configuration file](.github/workflows/fortress.yml).

Run all tests (fast):

```bash script
magex test
```

Run all tests with race detector (slower):
```bash script
magex test:race
```

Include the PostgreSQL store (the Postgres-backed tests skip without a database):

```bash script
TEST_DATABASE_URL=postgres://... go test ./... -race
```

Run the TypeScript client tests and the cross-language interop suite (see the [test-client README](test-client/README.md)):

```bash script
cd ts-client && npm ci && npm test
cd ../test-client && npm ci && SERVER_URL=http://localhost:8080 npm test
```

<br/>

## 🛠️ Code Standards
Read more about this Go project's [code standards](.github/CODE_STANDARDS.md).

<br/>

## 🤖 AI Usage & Assistant Guidelines
Read the [AI Usage & Assistant Guidelines](.github/tech-conventions/ai-compliance.md) for details on how AI is used in this project and how to interact with AI assistants.

<br/>

## 👥 Maintainers
| [<img src="https://github.com/sirdeggen.png" height="50" alt="Deggen" />](https://github.com/sirdeggen) | [<img src="https://github.com/mrz1836.png" height="50" alt="MrZ" />](https://github.com/mrz1836) |
|:-------------------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------------:|
|                                  [Deggen](https://github.com/sirdeggen)                                  |                                [MrZ](https://github.com/mrz1836)                                 |

<br/>

## 🤝 Contributing
View the [contributing guidelines](.github/CONTRIBUTING.md) and please follow the [code of conduct](.github/CODE_OF_CONDUCT.md).

### How can I help?
All kinds of contributions are welcome :raised_hands:!
The most basic way to show your support is to star :star2: the project, or to raise issues :speech_balloon:.

[![Stars](https://img.shields.io/github/stars/bsv-blockchain/go-private-backup-cache?label=Please%20like%20us&style=social&v=1)](https://github.com/bsv-blockchain/go-private-backup-cache/stargazers)

<br/>

## 📝 License

[![License](https://img.shields.io/badge/license-OpenBSV-blue?style=flat&logo=springsecurity&logoColor=white)](LICENSE)
