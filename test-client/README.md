# Interop test client

Unit tests cannot prove the wire protocol works — they never put a proof header on a real
socket. This drives the Go server with the actual TypeScript client (`../ts-client`), and
uses the client's exported proof primitives to hand-build the requests the client API
refuses to express: a body that does not hash to its signed digest, a replayed header, a
wrong content type. See `docs/authproof-protocol.md` for the protocol itself.

Build the client first — the `file:` dependency links `../ts-client`, and its `dist/` must
exist before `npm install` here:

```bash
cd ../ts-client && npm install && npm run build
cd ../test-client && npm install
```

Run the server with only an identity key. No `DATABASE_URL` is needed: without one the
server uses its in-memory store, which is exactly right for a throwaway interop run.

```bash
SERVER_PRIVATE_KEY=$(openssl rand -hex 32) go run ./cmd/server
```

Then:

```bash
SERVER_URL=http://localhost:8080 npm test
```

The oversize check (413) only runs when the cap is small enough to upload past cheaply;
restart the server with `MAX_BLOB_BYTES=1048576` to exercise it. The 8 MiB round-trip
runs against the default 200 MiB cap and is skipped below it.
