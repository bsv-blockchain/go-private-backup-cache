# @bsv/backup-cache-client

TypeScript client for [go-private-backup-cache](https://github.com/bsv-blockchain/go-private-backup-cache),
the zero-knowledge append-only wallet backup cache.

Every request carries a stateless per-request auth proof in one header (`X-Bsv-Auth`) —
no handshake, no session — signed under BRC-42/43 with protocol `[2, 'backup cache auth']`.
Uploads sign the body's sha256 into the proof and stream the body itself, so blobs up to
the server cap (200 MiB by default) never sit in memory on either side. The server only
ever sees ciphertext and a pseudonymous identity key; encrypt before you append.

## Install

```sh
npm install @bsv/backup-cache-client @bsv/sdk
```

`@bsv/sdk` (>= 2.4.1) is a peer dependency — the wallet you pass in comes from it.

## Usage

```ts
import { BackupCacheClient, BackupHttpError, ERR_SEQ_CONFLICT } from '@bsv/backup-cache-client'
import { CompletedProtoWallet, PrivateKey } from '@bsv/sdk'

const client = new BackupCacheClient({
  baseUrl: 'https://backup.example.com',
  wallet: new CompletedProtoWallet(PrivateKey.fromHex(backupPseudonymKeyHex))
})

// The server's blob cap and identity key (cached after the first call).
const { maxBlobBytes } = await client.limits()

// Append ciphertext. Pass a Blob to stream a large upload from disk.
const { seq, sha256 } = await client.append(deviceId, generation, 1, undefined, ciphertext)

// Restore: enumerate devices, list a generation, fetch blobs (buffered or streaming).
const devices = await client.manifest()
const entries = await client.index(deviceId, generation)
const bytes = await client.blob(deviceId, generation, seq)
const stream = await client.blobStream(deviceId, generation, seq)

// Housekeeping.
await client.pruneGeneration(deviceId, oldGeneration)
await client.deleteAccount() // erases everything for this identity

try {
  await client.append(deviceId, generation, 9, prev, ciphertext)
} catch (e) {
  if (e instanceof BackupHttpError && e.code === ERR_SEQ_CONFLICT) {
    // Another device advanced the log: resynchronise from the index, don't retry.
  }
}
```

The account is derived from the proof's identity key alone — there is no identity
parameter on any request, so one key can never address another key's log.
