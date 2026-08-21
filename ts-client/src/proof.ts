/**
 * Per-request auth proofs for the backup cache, wire-compatible with the Go server's
 * internal/authproof package.
 *
 * The signed bytes are @bsv/auth's canonical serialization (action\nidentityKey\n
 * expiresAt\nnonce), but the proof is built from the primitives rather than
 * `createAuthProof` because the action must carry the request URI — and for uploads the
 * body's sha256 — which the convenience wrapper has no slot for. Signing the digest
 * instead of the body is what lets both sides stream: the server authenticates from the
 * header alone and compares hashes only after the body has streamed to storage.
 */
import { createAuthSigData, serializeAuthSigData, type ProofSignerWallet } from '@bsv/auth'
import { Hash, Utils, type WalletProtocol } from '@bsv/sdk'

/** BRC-43 protocol both sides derive signing keys under. Must match the Go server. */
export const PROTOCOL: WalletProtocol = [2, 'backup cache auth']

/** The single header carrying the proof: base64 of the JSON wire shape below. */
export const AUTH_HEADER = 'X-Bsv-Auth'

/** Proof validity window in ms, matching @bsv/auth's default and the server's check. */
export const PROOF_WINDOW_MS = 120_000

/**
 * The JSON the header carries, verbatim what the Go server decodes. Flat rather than
 * @bsv/auth's `{data, signature}` nesting, and the signature travels as base64 of the
 * DER bytes rather than a JSON number array.
 */
export interface WireProof {
  action: string
  identityKey: string
  expiresAt: number
  nonce: string
  signature: string
}

/**
 * The canonical action string a proof authorizes.
 *
 * `requestURI` must be the literal path-plus-query as sent on the wire — the server
 * compares strings, byte for byte, with no canonicalization pass. `bodySha256Hex` is the
 * lowercase hex digest of the request body; omit it for bodyless requests.
 */
export function buildAction (method: string, requestURI: string, bodySha256Hex?: string): string {
  if (bodySha256Hex === undefined || bodySha256Hex === '') return `${method} ${requestURI}`
  return `${method} ${requestURI} sha256=${bodySha256Hex}`
}

/**
 * Sign `action` toward the server and render the header value.
 *
 * `now` is injectable for tests; expiry is always now + PROOF_WINDOW_MS because the
 * server refuses anything further out as a fabricated expiry.
 */
export async function signProofHeader (
  wallet: ProofSignerWallet,
  serverIdentityKey: string,
  action: string,
  now: number = Date.now()
): Promise<string> {
  const { publicKey: identityKey } = await wallet.getPublicKey({ identityKey: true })
  const data = createAuthSigData(action, identityKey, { windowMs: PROOF_WINDOW_MS }, now)
  const { signature } = await wallet.createSignature({
    data: serializeAuthSigData(data),
    protocolID: PROTOCOL,
    // The nonce doubles as the derivation keyID, so every proof signs under a fresh key.
    keyID: data.nonce,
    counterparty: serverIdentityKey
  })
  const proof: WireProof = {
    action: data.action,
    identityKey: data.identityKey,
    expiresAt: data.expiresAt,
    nonce: data.nonce,
    signature: Utils.toBase64(signature)
  }
  // The JSON is pure ASCII (base64, hex, digits), but round-tripping through UTF-8 bytes
  // avoids btoa's Latin-1 trap entirely and works identically in Node and browsers.
  return Utils.toBase64(Utils.toArray(JSON.stringify(proof), 'utf8'))
}

/**
 * Lowercase hex sha256 of an upload body, as bound into the action string.
 *
 * A Blob is hashed through its stream chunk by chunk — a blob can be as large as the
 * server cap (hundreds of MiB) and must never be resident in memory just to hash it.
 */
export async function bodySha256Hex (body: Uint8Array | Blob): Promise<string> {
  if (body instanceof Uint8Array) {
    return Utils.toHex(Hash.sha256(body))
  }
  const hasher = new Hash.SHA256()
  const reader = body.stream().getReader()
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    hasher.update(value)
  }
  return hasher.digestHex()
}
