/**
 * HTTP client for the encrypted backup log (go-private-backup-cache).
 *
 * Every authenticated request carries one stateless proof header — no handshake, no
 * session, no signed response envelope — so uploads and downloads stream end to end.
 * There is deliberately no identity parameter on any request: the server derives the
 * account from the proof's identity key and nothing else, which is what makes it
 * impossible to address someone else's log.
 */
import { type ProofSignerWallet } from '@bsv/auth'
import { AUTH_HEADER, bodySha256Hex, buildAction, signProofHeader } from './proof.js'

/** One log entry's metadata, as reported by the index. */
export interface LogEntry {
  seq: number
  sha256: string
  prevSha256?: string
  size: number
  createdAt: string
}

/** One device+generation head, as reported by the manifest. */
export interface DeviceSummary {
  deviceId: string
  generation: number
  headSeq: number
  headSha256: string
  totalBytes: number
  updatedAt: string
}

/** The server's caps and identity, from unauthenticated GET /v1/limits. */
export interface Limits {
  maxBlobBytes: number
  maxBodyBytes: number
  serverIdentityKey: string
}

/** Thrown when the server rejects a request; `code` is the ERR_* envelope code. */
export class BackupHttpError extends Error {
  constructor (readonly status: number, readonly code: string, description: string) {
    super(`${code}: ${description}`)
    this.name = 'BackupHttpError'
  }
}

/** The server's sequence-conflict code. Callers resynchronise rather than retrying. */
export const ERR_SEQ_CONFLICT = 'ERR_SEQ_CONFLICT'

/** The server's oversize code, from the 413 the size guard sends before auth runs. */
export const ERR_BLOB_TOO_LARGE = 'ERR_BLOB_TOO_LARGE'

export interface BackupCacheClientOptions {
  /**
   * Origin of the backup service, without a trailing slash or path prefix. Request URIs
   * are appended verbatim and also signed into the auth proof, so any prefix the server
   * does not see identically would fail every proof.
   */
  baseUrl: string
  /** Wallet the proofs sign with, e.g. `new CompletedProtoWallet(priv)`. */
  wallet: ProofSignerWallet
  /** Injectable transport for tests; defaults to the global fetch. */
  fetch?: typeof fetch
}

export class BackupCacheClient {
  private readonly baseUrl: string
  private readonly wallet: ProofSignerWallet
  private readonly fetchImpl: typeof fetch
  private cachedLimits?: Limits

  constructor (opts: BackupCacheClientOptions) {
    // A trailing slash would put "//" on the wire while the signed action says "/",
    // failing every proof — strip it rather than document it.
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '')
    this.wallet = opts.wallet
    // Wrapped so the global fetch keeps its own receiver; a bare method reference throws
    // "Illegal invocation" in browsers.
    this.fetchImpl = opts.fetch ?? ((input, init) => fetch(input, init))
  }

  /**
   * The server's caps and identity key. Cached after the first call: the identity key is
   * needed to sign every proof and does not change while the client lives.
   */
  async limits (): Promise<Limits> {
    if (this.cachedLimits !== undefined) return this.cachedLimits
    const res = await this.fetchImpl(`${this.baseUrl}/v1/limits`, { method: 'GET' })
    const body = await this.okJson(res)
    const maxBlobBytes = Number(body.maxBlobBytes)
    const maxBodyBytes = Number(body.maxBodyBytes)
    const serverIdentityKey = String(body.serverIdentityKey ?? '')
    // Every later proof signs against serverIdentityKey, so caching a 200 that is not
    // actually a caps document — a captive portal, a misrouted proxy, a stub returning
    // {"status":"ok"} — would poison every request for the client's lifetime. Refuse it
    // here and leave the cache empty so the next call retries against the real server.
    if (!Number.isFinite(maxBlobBytes) || maxBlobBytes <= 0 ||
      !/^0[23][0-9a-f]{64}$/.test(serverIdentityKey)) {
      throw new BackupHttpError(res.status, 'ERR_BAD_LIMITS',
        'The limits response is not a usable caps document; not caching it.')
    }
    this.cachedLimits = { maxBlobBytes, maxBodyBytes, serverIdentityKey }
    return this.cachedLimits
  }

  /**
   * Append one blob.
   *
   * The body's sha256 is signed into the proof, then the body itself is handed to fetch —
   * a Blob streams from disk without ever being resident. The server hashes what arrives
   * and keeps nothing on a mismatch.
   */
  async append (
    deviceId: string,
    generation: number,
    seq: number,
    prevSha256: string | undefined,
    body: Uint8Array | Blob
  ): Promise<{ seq: number, sha256: string, size: number }> {
    let uri = `/v1/log/${encodeURIComponent(deviceId)}?seq=${seq}&generation=${generation}`
    if (prevSha256 !== undefined && prevSha256 !== '') {
      uri += `&prevSha256=${encodeURIComponent(prevSha256)}`
    }
    const digest = await bodySha256Hex(body)
    const res = await this.authedFetch('POST', uri, digest, body)
    const json = await this.okJson(res)
    return { seq: Number(json.seq), sha256: String(json.sha256), size: Number(json.size) }
  }

  /** Fetch one blob's ciphertext fully buffered. For large blobs prefer blobStream. */
  async blob (deviceId: string, generation: number, seq: number): Promise<Uint8Array> {
    const res = await this.blobResponse(deviceId, generation, seq)
    return new Uint8Array(await res.arrayBuffer())
  }

  /**
   * Fetch one blob's ciphertext as a stream. The server sends Content-Length up front,
   * so callers wanting progress can read it from `limits`-sized chunks themselves; this
   * method only promises the bytes never sit in memory whole.
   */
  async blobStream (deviceId: string, generation: number, seq: number): Promise<ReadableStream<Uint8Array>> {
    const res = await this.blobResponse(deviceId, generation, seq)
    if (res.body === null) {
      // Fetch implementations without response streaming (or a HEAD-like empty body)
      // cannot satisfy this method's contract; blob() still works there.
      throw new BackupHttpError(res.status, 'ERR_NO_STREAM', 'Response carried no readable body stream.')
    }
    return res.body
  }

  /** List entry metadata for one generation, oldest first. */
  async index (deviceId: string, generation: number, from = 1, limit?: number): Promise<LogEntry[]> {
    let uri = `/v1/log/${encodeURIComponent(deviceId)}?generation=${generation}&from=${from}`
    if (limit !== undefined) uri += `&limit=${limit}`
    const res = await this.authedFetch('GET', uri)
    const json = await this.okJson(res)
    return (json.entries ?? []) as LogEntry[]
  }

  /** Every device and generation belonging to this identity. The restore entry point. */
  async manifest (): Promise<DeviceSummary[]> {
    const res = await this.authedFetch('GET', '/v1/manifest')
    const json = await this.okJson(res)
    return (json.devices ?? []) as DeviceSummary[]
  }

  /** Drop a superseded generation. The server refuses anything within its retained window. */
  async pruneGeneration (deviceId: string, generation: number): Promise<void> {
    const uri = `/v1/generation/${encodeURIComponent(deviceId)}/${generation}`
    const res = await this.authedFetch('DELETE', uri)
    if (!res.ok) await this.throwFor(res)
  }

  /**
   * Erase every generation across all devices — the GDPR Article 17 path. A separate
   * route from pruning because pruning refuses the newest generations by design.
   * Idempotent server-side: erasing an empty account answers with a count of zero.
   */
  async deleteAccount (): Promise<{ deleted: number }> {
    const res = await this.authedFetch('DELETE', '/v1/account')
    const json = await this.okJson(res)
    return { deleted: Number(json.deleted ?? 0) }
  }

  private async blobResponse (deviceId: string, generation: number, seq: number): Promise<Response> {
    const uri = `/v1/log/${encodeURIComponent(deviceId)}/${seq}?generation=${generation}`
    const res = await this.authedFetch('GET', uri)
    if (!res.ok) await this.throwFor(res)
    return res
  }

  /**
   * Sign and send. `uri` is passed both into the action and to fetch unmodified — the
   * server compares the signed action against the wire's request URI byte for byte, so
   * one string must serve both.
   */
  private async authedFetch (
    method: string,
    uri: string,
    bodySha256?: string,
    body?: Uint8Array | Blob
  ): Promise<Response> {
    const { serverIdentityKey } = await this.limits()
    const action = buildAction(method, uri, bodySha256)
    const headers: Record<string, string> = {
      [AUTH_HEADER]: await signProofHeader(this.wallet, serverIdentityKey, action)
    }
    const init: RequestInit = { method, headers }
    if (body !== undefined) {
      headers['Content-Type'] = 'application/octet-stream'
      init.body = body as BodyInit
    }
    return await this.fetchImpl(this.baseUrl + uri, init)
  }

  private async okJson (res: Response): Promise<Record<string, unknown>> {
    if (!res.ok) await this.throwFor(res)
    return (await res.json()) as Record<string, unknown>
  }

  private async throwFor (res: Response): Promise<never> {
    let code = 'ERR_UNKNOWN'
    let description = res.statusText
    try {
      const body = (await res.json()) as { code?: string, description?: string }
      code = body.code ?? code
      description = body.description ?? description
    } catch {
      // Non-JSON error body; the status alone has to carry the meaning.
    }
    throw new BackupHttpError(res.status, code, description)
  }
}
