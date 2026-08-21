// Interop proof: the real TypeScript client (../ts-client) against the Go server, over
// the stateless per-request proof protocol (docs/authproof-protocol.md). Everything the
// client API can express goes through BackupCacheClient; the cases it deliberately cannot
// — a tampered body, a replayed header, a wrong content type — are built as raw fetches
// from the client's own exported proof primitives, so even the hostile requests sign
// exactly the bytes the server verifies.
import {
  AUTH_HEADER, BackupCacheClient, BackupHttpError, ERR_BLOB_TOO_LARGE, ERR_SEQ_CONFLICT,
  bodySha256Hex, buildAction, signProofHeader
} from '@bsv/backup-cache-client'
import { CompletedProtoWallet, PrivateKey } from '@bsv/sdk'
import { createHash, randomBytes } from 'crypto'

const BASE = process.env.SERVER_URL ?? 'http://localhost:8080'
const OCTET = 'application/octet-stream'

const results = []
function check (name, cond, detail = '') {
  results.push({ name, ok: !!cond, detail })
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`)
}

// The client throws BackupHttpError for every refusal, so refusals are proven by
// catching. Anything else (a network failure, a client bug) is returned rather than
// rethrown: the run's tally is worth more than a stack trace.
async function refusal (fn) {
  try {
    await fn()
    return null
  } catch (err) {
    return err
  }
}

function describe (err) {
  if (err === null) return 'no error thrown'
  if (err instanceof BackupHttpError) return `status ${err.status} code ${err.code}`
  return String(err)
}

function isRefusal (err, status, code) {
  return err instanceof BackupHttpError && err.status === status && err.code === code
}

// One wallet per identity: the account is the proof's identity key and nothing else, so
// two fresh keys ARE two isolated tenants — no signup, no configuration.
function identity () {
  const wallet = new CompletedProtoWallet(PrivateKey.fromRandom())
  return { wallet, client: new BackupCacheClient({ baseUrl: BASE, wallet }) }
}

const alice = identity()
const bob = identity()
const device = randomBytes(16).toString('hex')
const blob = randomBytes(4096)

// 1. Upload through the client: one proof header, no handshake round-trips.
const expectSha = createHash('sha256').update(blob).digest('hex')
const put = await alice.client.append(device, 1, 1, undefined, blob)
check('append succeeds (201) and the server-reported sha256 matches the uploaded bytes',
  put.seq === 1 && put.size === blob.length && put.sha256 === expectSha,
  `seq ${put.seq} size ${put.size} sha match=${put.sha256 === expectSha}`)

// 2. Round-trip fidelity — the property everything else rests on.
const back = Buffer.from(await alice.client.blob(device, 1, 1))
check('blob round-trips byte-exactly', back.equals(blob),
  `${back.length}/${blob.length} bytes, equal=${back.equals(blob)}`)

// 3. Contiguous-sequence enforcement, surfaced as a typed error the caller can branch on.
const dup = await refusal(() => alice.client.append(device, 1, 1, undefined, randomBytes(64)))
check('re-writing a sequence is refused (409 ERR_SEQ_CONFLICT)',
  isRefusal(dup, 409, ERR_SEQ_CONFLICT), describe(dup))

// 4.
const gap = await refusal(() => alice.client.append(device, 1, 9, undefined, randomBytes(64)))
check('skipping a sequence is refused (409 ERR_SEQ_CONFLICT)',
  isRefusal(gap, 409, ERR_SEQ_CONFLICT), describe(gap))

// 5. Limits must be reachable without a proof: the serverIdentityKey it reports is what a
// client needs BEFORE it can sign anything. The raw fetch here (not the client) is the
// point — no header, no wallet.
const limitsRes = await fetch(`${BASE}/v1/limits`)
const limits = await limitsRes.json()
check('limits endpoint is public and reports the cap and the server identity key',
  limitsRes.status === 200 && Number.isInteger(limits.maxBlobBytes) &&
    limits.maxBodyBytes === limits.maxBlobBytes &&
    /^0[23][0-9a-f]{64}$/.test(String(limits.serverIdentityKey)),
  `maxBlobBytes ${limits.maxBlobBytes} maxBodyBytes ${limits.maxBodyBytes} key ${String(limits.serverIdentityKey).slice(0, 8)}…`)

// Uploading past a 200 MiB cap would move gigabytes through the signing path for one
// assertion, so the oversize check runs only against a small cap. Not silently skipped:
// it prints why, and how to force it.
const OVERSIZE_CEILING = 8 * 1024 * 1024
if (limits.maxBlobBytes <= OVERSIZE_CEILING) {
  const big = await refusal(() =>
    alice.client.append(device, 1, 2, undefined, randomBytes(limits.maxBlobBytes + 1)))
  check('oversize blob is rejected (413 ERR_BLOB_TOO_LARGE)',
    isRefusal(big, 413, ERR_BLOB_TOO_LARGE), describe(big))
} else {
  console.log(`SKIP  oversize blob is rejected (413)  — server cap is ${limits.maxBlobBytes} bytes; ` +
    'rerun the server with MAX_BLOB_BYTES=1048576 to exercise it')
}

// 6. Manifest is scoped to the caller.
const man = await alice.client.manifest()
check("manifest lists the caller's own device and nothing else",
  man.length === 1 && man[0].deviceId === device && man[0].headSeq === 1,
  JSON.stringify(man.map(d => ({ deviceId: d.deviceId, headSeq: d.headSeq }))))

// 7. THE security property: a different identity cannot read the same coordinates, and
// cannot even learn they exist — 404, indistinguishable from "no such blob".
const steal = await refusal(() => bob.client.blob(device, 1, 1))
check('another identity cannot read the blob (404)', isRefusal(steal, 404, 'ERR_BLOB_NOT_FOUND'),
  describe(steal))

const bobMan = await bob.client.manifest()
check('another identity sees an empty manifest', bobMan.length === 0, JSON.stringify(bobMan))

// 8. Same coordinates, different identity: the write lands in bob's own namespace and
// alice's blob is untouched.
const overwrite = await bob.client.append(device, 1, 1, undefined, Buffer.from('bob-was-here'))
const stillMine = Buffer.from(await alice.client.blob(device, 1, 1))
check('another identity writing the same coordinates does not clobber',
  overwrite.seq === 1 && stillMine.equals(blob),
  `their write seq=${overwrite.seq}, mine intact=${stillMine.equals(blob)}`)

// 9. JSON upload is refused — there is exactly one upload encoding. The client cannot
// send a wrong content type by construction, so this is a raw fetch under a valid proof:
// the refusal must come from the media-type check, not from auth.
const jsonBody = Buffer.from(JSON.stringify({ a: 1 }))
const jsonUri = `/v1/log/${device}?seq=2&generation=1`
const jsonHeader = await signProofHeader(alice.wallet, limits.serverIdentityKey,
  buildAction('POST', jsonUri, await bodySha256Hex(jsonBody)))
const asJson = await fetch(BASE + jsonUri, {
  method: 'POST',
  headers: { [AUTH_HEADER]: jsonHeader, 'Content-Type': 'application/json' },
  body: jsonBody
})
check('JSON upload refused (415)', asJson.status === 415, `status ${asJson.status}`)

// 10. Wrong content: the proof signs the digest of one body and the wire carries another.
// The server must stream the impostor to EOF, notice the hash mismatch, and keep nothing.
// Built from the primitives because the client always signs the body it sends.
const declared = randomBytes(64)
const impostor = randomBytes(64)
const tamperUri = `/v1/log/${device}?seq=2&generation=1`
const tamperHeader = await signProofHeader(alice.wallet, limits.serverIdentityKey,
  buildAction('POST', tamperUri, await bodySha256Hex(declared)))
const tampered = await fetch(BASE + tamperUri, {
  method: 'POST',
  headers: { [AUTH_HEADER]: tamperHeader, 'Content-Type': OCTET },
  body: impostor
})
const tamperedBody = await tampered.json().catch(() => ({}))
check('a body that does not hash to its signed digest is refused (400 ERR_BODY_DIGEST_MISMATCH)',
  tampered.status === 400 && tamperedBody.code === 'ERR_BODY_DIGEST_MISMATCH',
  `status ${tampered.status} code ${String(tamperedBody.code)}`)

// The refusal alone is half the property: the impostor bytes streamed into the store
// before the hash check could fail, so the rollback must be proven too. Deliberately not
// inside any cap-gated block — this must hold at every cap, including the small one the
// README says to rerun with.
const afterTamper = await alice.client.index(device, 1)
check('the tampered upload stored nothing (index still ends at seq 1)',
  afterTamper.length === 1 && afterTamper[0].seq === 1,
  `seqs ${JSON.stringify(afterTamper.map(e => e.seq))}`)

// 11. Replay: the same header, byte for byte, on a fresh connection. The first use burns
// the nonce; the second must die at auth even though the signature is still valid and the
// window still open.
const replayHeader = await signProofHeader(alice.wallet, limits.serverIdentityKey,
  buildAction('GET', '/v1/manifest'))
const firstUse = await fetch(`${BASE}/v1/manifest`, { headers: { [AUTH_HEADER]: replayHeader } })
const replay = await fetch(`${BASE}/v1/manifest`, { headers: { [AUTH_HEADER]: replayHeader } })
check('a captured proof header replayed verbatim is refused (401)',
  firstUse.status === 200 && replay.status === 401,
  `first ${firstUse.status}, replay ${replay.status}`)

// 12. A large blob round-trips. 8 MiB is big enough to cross every buffering boundary
// (chunked hashing, streamed storage, Content-Length response) while staying cheap to
// sign. Appending at seq 2 also re-proves the tampered upload above stored nothing — a
// kept row would make this a sequence conflict.
const EIGHT_MIB = 8 * 1024 * 1024
if (limits.maxBlobBytes >= EIGHT_MIB) {
  const bigBlob = randomBytes(EIGHT_MIB)
  const bigPut = await alice.client.append(device, 1, 2, put.sha256, bigBlob)
  const bigBack = Buffer.from(await alice.client.blob(device, 1, 2))
  check('an 8 MiB blob round-trips byte-exactly',
    bigPut.size === EIGHT_MIB && bigBack.equals(bigBlob),
    `${bigBack.length}/${bigBlob.length} bytes, equal=${bigBack.equals(bigBlob)}`)
} else {
  console.log(`SKIP  an 8 MiB blob round-trips byte-exactly  — server cap is ${limits.maxBlobBytes} bytes`)
}

// 13. Retention floor.
const del = await refusal(() => alice.client.pruneGeneration(device, 1))
check('deleting the only generation is refused (409 ERR_RETENTION_GUARD)',
  isRefusal(del, 409, 'ERR_RETENTION_GUARD'), describe(del))

// 14. Erasure on request. Runs last, deliberately: it removes everything the steps above
// wrote, so nothing after it could rely on that data. Bob holds exactly the one blob from
// step 8 — his erasure must count that and only that.
const bobErase = await bob.client.deleteAccount()
const survivor = Buffer.from(await alice.client.blob(device, 1, 1))
check("bob erasing his own account cannot touch alice's data (deleted 1, hers intact)",
  bobErase.deleted === 1 && survivor.equals(blob),
  `deleted ${bobErase.deleted}, alice intact=${survivor.equals(blob)}`)

const erase = await alice.client.deleteAccount()
check('erasure removes the generation the retention guard protected',
  erase.deleted >= 1, `deleted ${erase.deleted}`)

const gone = await refusal(() => alice.client.blob(device, 1, 1))
check('erased blob is gone (404)', isRefusal(gone, 404, 'ERR_BLOB_NOT_FOUND'), describe(gone))

const again = await alice.client.deleteAccount()
check('erasure is idempotent (deleted 0)', again.deleted === 0, `deleted ${again.deleted}`)

const failed = results.filter(r => !r.ok)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
process.exit(failed.length === 0 ? 0 : 1)
