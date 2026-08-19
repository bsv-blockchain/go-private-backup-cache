// Interop proof: a real @bsv/sdk 2.4.0 AuthFetch client against the Go server.
// Verifies the BRC-103/104 handshake, raw binary round-trip, sequence conflict handling,
// and — most importantly — that one identity cannot reach another's blobs.
import pkg from '@bsv/sdk'
import { randomBytes } from 'crypto'

const { AuthFetch, CompletedProtoWallet, PrivateKey } = pkg
const BASE = process.env.SERVER_URL ?? 'http://localhost:8080'
const OCTET = 'application/octet-stream'

function client () {
  const priv = PrivateKey.fromRandom()
  return { f: new AuthFetch(new CompletedProtoWallet(priv)), key: priv.toPublicKey().toString() }
}

const results = []
function check (name, cond, detail = '') {
  results.push({ name, ok: !!cond, detail })
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`)
}

const alice = client()
const bob = client()
const device = randomBytes(16).toString('hex')
const blob = randomBytes(4096)

// 1. Handshake + raw binary upload.
const put = await alice.f.fetch(`${BASE}/v1/log/${device}?seq=1&generation=1`, {
  method: 'POST', headers: { 'Content-Type': OCTET }, body: blob,
})
check('BRC-103/104 handshake + raw octet-stream upload', put.status === 201, `status ${put.status}`)
const putBody = await put.json()

// 2. Round-trip fidelity — the property everything else rests on.
const got = await alice.f.fetch(`${BASE}/v1/log/${device}/1?generation=1`, { method: 'GET' })
const back = Buffer.from(await got.arrayBuffer())
check('blob round-trips byte-exactly', got.status === 200 && back.equals(blob),
  `${back.length}/${blob.length} bytes, equal=${back.equals(blob)}`)

// 3. sha256 reported matches what we sent.
const { createHash } = await import('crypto')
const expectSha = createHash('sha256').update(blob).digest('hex')
check('server-reported sha256 matches the uploaded bytes', putBody.sha256 === expectSha)

// 4. Contiguous-sequence enforcement.
const dup = await alice.f.fetch(`${BASE}/v1/log/${device}?seq=1&generation=1`, {
  method: 'POST', headers: { 'Content-Type': OCTET }, body: randomBytes(64),
})
check('re-writing a sequence is refused (409)', dup.status === 409, `status ${dup.status}`)

const gap = await alice.f.fetch(`${BASE}/v1/log/${device}?seq=9&generation=1`, {
  method: 'POST', headers: { 'Content-Type': OCTET }, body: randomBytes(64),
})
check('skipping a sequence is refused (409)', gap.status === 409, `status ${gap.status}`)

// 5. Size cap.
const big = await alice.f.fetch(`${BASE}/v1/log/${device}?seq=2&generation=1`, {
  method: 'POST', headers: { 'Content-Type': OCTET }, body: randomBytes(1024 * 1024 + 1),
})
check('oversize blob rejected (413)', big.status === 413, `status ${big.status}`)

// 6. Manifest is scoped to the caller.
const man = await alice.f.fetch(`${BASE}/v1/manifest`, { method: 'GET' })
const manBody = await man.json()
check('manifest lists the caller\'s own device', manBody.devices?.[0]?.deviceId === device)

// 7. THE security property: a different identity cannot read the same coordinates.
const steal = await bob.f.fetch(`${BASE}/v1/log/${device}/1?generation=1`, { method: 'GET' })
check('another identity cannot read the blob (404)', steal.status === 404, `status ${steal.status}`)

const bobMan = await bob.f.fetch(`${BASE}/v1/manifest`, { method: 'GET' })
const bobManBody = await bobMan.json()
check('another identity sees an empty manifest',
  Array.isArray(bobManBody.devices) && bobManBody.devices.length === 0,
  JSON.stringify(bobManBody.devices))

// 8. Another identity cannot overwrite; and the original survives.
const overwrite = await bob.f.fetch(`${BASE}/v1/log/${device}?seq=1&generation=1`, {
  method: 'POST', headers: { 'Content-Type': OCTET }, body: Buffer.from('bob-was-here'),
})
const stillMine = await alice.f.fetch(`${BASE}/v1/log/${device}/1?generation=1`, { method: 'GET' })
const stillBytes = Buffer.from(await stillMine.arrayBuffer())
check('another identity writing the same coordinates does not clobber',
  overwrite.status === 201 && stillBytes.equals(blob),
  `their write=${overwrite.status}, mine intact=${stillBytes.equals(blob)}`)

// 9. JSON upload is refused — there is exactly one upload encoding.
const asJson = await alice.f.fetch(`${BASE}/v1/log/${device}?seq=2&generation=1`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ a: 1 }),
})
check('JSON upload refused (415)', asJson.status === 415, `status ${asJson.status}`)

// 10. Retention floor.
const del = await alice.f.fetch(`${BASE}/v1/generation/${device}/1`, { method: 'DELETE' })
check('deleting the only generation is refused (409)', del.status === 409, `status ${del.status}`)

// 11. Erasure on request. Runs last, deliberately: it removes everything the steps above
// wrote, so nothing after it could rely on that data.
const bobErase = await bob.f.fetch(`${BASE}/v1/account`, { method: 'DELETE' })
const bobBody = await bobErase.json().catch(() => ({}))
check('bob erasing his own account cannot touch alice (deleted 0)',
  bobErase.status === 200 && bobBody.deleted === 0,
  `status ${bobErase.status} deleted ${String(bobBody.deleted)}`)

const stillThere = await alice.f.fetch(`${BASE}/v1/log/${device}/1?generation=1`, { method: 'GET' })
check("alice's blob survived bob's erasure", stillThere.status === 200, `status ${stillThere.status}`)

const erase = await alice.f.fetch(`${BASE}/v1/account`, { method: 'DELETE' })
const erased = await erase.json().catch(() => ({}))
check('erasure removes the retained generation prune refused',
  erase.status === 200 && erased.deleted >= 1,
  `status ${erase.status} deleted ${String(erased.deleted)}`)

const gone = await alice.f.fetch(`${BASE}/v1/log/${device}/1?generation=1`, { method: 'GET' })
check('erased blob is gone (404)', gone.status === 404, `status ${gone.status}`)

const again = await alice.f.fetch(`${BASE}/v1/account`, { method: 'DELETE' })
const againBody = await again.json().catch(() => ({}))
check('erasure is idempotent (200, deleted 0)',
  again.status === 200 && againBody.deleted === 0,
  `status ${again.status} deleted ${String(againBody.deleted)}`)

const failed = results.filter(r => !r.ok)
console.log(`\n${results.length - failed.length}/${results.length} passed`)
process.exit(failed.length === 0 ? 0 : 1)
