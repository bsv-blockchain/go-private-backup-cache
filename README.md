# go-private-backup-cache

An append-only, zero-knowledge cache for encrypted wallet-backup blobs.

A BSV wallet cannot be recovered from its seed alone. Spending an output requires derivation
metadata that exists only in the wallet's local database — change outputs carry a random
derivation suffix, and received BRC-29 outputs carry a `derivationPrefix`, `derivationSuffix`
and `senderIdentityKey` chosen by the sender. None of it is on-chain, and there is no rescan
path. A user who dutifully wrote down their recovery phrase and then lost their phone still
cannot spend their coins.

This service holds the other half. Wallets push their database to it as encrypted delta
chunks; a reinstalled wallet replays them and is whole again. It turns recovery from
"you need **both** the phrase and the device" into "you need **only** the phrase".

## What the server can and cannot see

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

## Why the service is free, permanently

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

## API

Everything except `/health` and `/v1/limits` requires an `X-Bsv-Auth` proof header —
one signed proof per request, verified before the body is read, no handshake and no
session. The scheme is `@bsv/auth`-compatible and specified in
[docs/authproof-protocol.md](docs/authproof-protocol.md).
`{deviceId}` is a client-generated opaque `[a-f0-9]{32}`. Sequences are 1-based and
contiguous within a `(pseudonym, deviceId, generation)`.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/health` | Unauthenticated |
| `GET` | `/v1/limits` | Unauthenticated; `maxBlobBytes`, `maxBodyBytes`, `serverIdentityKey` |
| `GET` | `/v1/manifest` | Devices and generations for the caller |
| `POST` | `/v1/log/{deviceId}?seq=&generation=&prevSha256=` | Raw `application/octet-stream` body, streamed |
| `GET` | `/v1/log/{deviceId}?generation=&from=&limit=` | Entry metadata |
| `GET` | `/v1/log/{deviceId}/{seq}?generation=` | Raw ciphertext, streamed, `Content-Length` set |
| `DELETE` | `/v1/generation/{deviceId}/{generation}` | Prune an old generation |
| `DELETE` | `/v1/account` | Erase every generation for the caller (GDPR Art. 17) |

Uploads are raw binary, not base64 — the body on the wire is the blob, byte for byte, and
its sha256 is bound into the auth proof. Both directions stream: a blob is never resident
in server memory.

Errors use `{"status":"error","code":"ERR_...","description":"..."}`.

Clients: [`client/`](client/) (Go) and [`ts-client/`](ts-client/) (TypeScript,
`@bsv/backup-cache-client`) ship in this repo and speak the whole protocol.

### Retention

The current and previous generation are kept — two, so a compaction that fails partway never
leaves a user with zero recoverable backups. Compaction is client-driven: write a full
snapshot as generation N+1, then delete N-2.

**There is no time-based expiry.** A pseudonym untouched for years belongs to precisely the
user this service exists for: someone who lost their device and has not yet replaced it.

## Running it

```bash
cp .env.example .env
# set SERVER_PRIVATE_KEY to 64 hex characters
go run ./cmd/server
```

Without `DATABASE_URL` the service runs on an in-memory store and logs a warning. That is for
development only — everything is lost on restart, which for a backup service is a bad
surprise.

```bash
go test ./... -race -cover
TEST_DATABASE_URL=postgres://... go test ./... -race   # includes the Postgres store
```

## Operational notes

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
