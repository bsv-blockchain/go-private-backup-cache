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
- **The account address is a pseudonym.** Clients authenticate over BRC-103/104 using a key
  derived from their wallet seed, not their wallet identity key. The server stores blobs
  under whatever key authenticated, so it never learns the on-chain identity.
- **There is no identity parameter anywhere in the API.** The account is taken from the
  authenticated session and nothing else. A client cannot name another account to read or
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
  not references. Delivered inside a request BRC-104 has already bound to the pseudonym, it
  is a signed assertion that this pseudonym controls those outpoints.
- **A chain the operator can walk.** Payment *n*'s change funds payment *n+1*, so two
  payments are enough to follow the wallet forward with any public indexer. Change amounts
  additionally disclose balance and its trajectory.
- **A join that needs no chain analysis at all.** Wallets already send their real identity
  key in cleartext to ordinary BRC-121 merchants, and every BRC-103 peer learns it by
  construction. One join against any service holding both that key and an outpoint is enough.
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

Everything except `/health`, `/v1/limits` and `/.well-known/auth` requires BRC-103/104
authentication.
`{deviceId}` is a client-generated opaque `[a-f0-9]{32}`. Sequences are 1-based and
contiguous within a `(pseudonym, deviceId, generation)`.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/health` | Unauthenticated |
| `GET` | `/v1/limits` | Unauthenticated; `maxBlobBytes` and `maxBodyBytes` |
| `GET` | `/v1/manifest` | Devices and generations for the caller |
| `POST` | `/v1/log/{deviceId}?seq=&generation=&prevSha256=` | Raw `application/octet-stream` body |
| `GET` | `/v1/log/{deviceId}?generation=&from=&limit=` | Entry metadata |
| `GET` | `/v1/log/{deviceId}/{seq}?generation=` | Raw ciphertext |
| `DELETE` | `/v1/generation/{deviceId}/{generation}` | Prune an old generation |
| `DELETE` | `/v1/account` | Erase every generation for the caller (GDPR Art. 17) |

Uploads are raw binary, not base64. This requires **`@bsv/sdk` 2.4.0** on the client: 2.1.9's
`AuthFetch` tested `typeof body === 'object'` ahead of its binary branches, so a `Uint8Array`
body was JSON-stringified into `{"0":12,...}`. Downloads are unaffected on both versions.

Errors use `{"status":"error","code":"ERR_...","description":"..."}`.

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

- **Mount at the origin root.** The auth middleware intercepts `POST /.well-known/auth` on an
  exact path compare, and TypeScript clients always post the handshake to the origin root.
  Mounting under a subtree makes every request 401 with `session-not-found`.
- **Single instance.** Sessions are in-process. Running replicas requires sticky sessions or
  a shared `auth.SessionManager` (five methods); none ships with the library. The failure mode
  is a handshake on one replica and a request on another.
- **Blobs are capped at 1 MiB.** Streaming is impossible behind the auth middleware — its
  response wrapper buffers in order to sign, and implements neither `http.Flusher` nor
  `http.Hijacker` — so every request is fully held in memory and the cap is what keeps that
  safe.
- **Oversize uploads answer 413 before authentication.** The size guard sits ahead of the
  auth middleware and overrides it. Without that, an oversize body failed the middleware's read
  while it built the signature payload, and the caller was told `invalid authentication` —
  sending them to debug BRC-31 headers over what was only ever a size problem. The 413 cannot
  itself be signed (refusing to read the body is the point), so `AuthFetch` still wraps it in a
  missing-headers message: clients should branch on the status or on `ERR_BLOB_TOO_LARGE`, never
  on the message text.
- **The cap is published at `GET /v1/limits`**, unauthenticated, so a client can read it instead
  of carrying its own copy that drifts out of sync with the deployment. The number is not a
  secret and knowing it grants no capability.
- **The server wallet holds no funds.** `CompletedProtoWallet` is key-only: it cannot spend,
  so it cannot be drained.
