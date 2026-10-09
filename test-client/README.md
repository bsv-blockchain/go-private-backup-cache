# Interop test client

Unit tests cannot prove the wire protocol works — they never put a proof header on a real
socket. This drives the Go server with the actual TypeScript client (`../ts-client`), and
uses the client's exported proof primitives to hand-build the requests the client API
refuses to express: a body that does not hash to its signed digest, a replayed header, a
wrong content type. See `docs/authproof-protocol.md` for the protocol itself.

This suite and `../ts-client` are one npm workspace, rooted at the repository root, with a
single lockfile there. The workspace links `@bsv/backup-cache-client` to `../ts-client`
(the `"*"` range always resolves to that local copy, never the published package), and
both share one `@bsv/sdk`, the way a real consumer satisfies the client's peer dependency.
Install from the repository root, then build the client, whose `dist/` is what this suite
imports:

```bash
npm install
npm run build --workspace ts-client
```

Run the server with only an identity key. No `DATABASE_URL` is needed: without one the
server uses its in-memory store, which is exactly right for a throwaway interop run.

```bash
SERVER_PRIVATE_KEY=$(openssl rand -hex 32) go run ./cmd/server
```

Then, from the repository root:

```bash
SERVER_URL=http://localhost:8080 npm test --workspace test-client
```

The oversize check (413) only runs when the cap is small enough to upload past cheaply;
restart the server with `MAX_BLOB_BYTES=1048576` to exercise it. The 8 MiB round-trip
runs against the default 200 MiB cap and is skipped below it. CI runs the suite against
both caps, so every check runs on every pull request.
