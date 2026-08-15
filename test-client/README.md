# Interop test client

Unit tests cannot prove BRC-103/104 works — they never exercise the handshake or the
request framing. This drives the server with the real `@bsv/sdk` client instead.

It requires **@bsv/sdk 2.4.0**. On 2.1.9 the raw binary upload fails: `AuthFetch`
tested `typeof body === 'object'` ahead of its binary branches, so a `Uint8Array` body was
JSON-stringified into `{"0":12,...}`.

```bash
npm install
SERVER_URL=http://localhost:8080 npm test
```

If the first check fails, the usual cause is the auth middleware being mounted under a
subtree rather than the origin root — the client posts its handshake to
`${origin}/.well-known/auth`, so it never reaches the middleware.
