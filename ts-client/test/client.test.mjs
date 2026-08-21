import { test } from 'node:test'
import assert from 'node:assert/strict'
import { CompletedProtoWallet, PrivateKey } from '@bsv/sdk'
import { BackupCacheClient, BackupHttpError, ERR_SEQ_CONFLICT } from '../dist/index.js'

const wallet = new CompletedProtoWallet(PrivateKey.fromHex('11'.repeat(32)))
const serverWallet = new CompletedProtoWallet(PrivateKey.fromHex('22'.repeat(32)))

async function serverIdentityKey () {
  const { publicKey } = await serverWallet.getPublicKey({ identityKey: true })
  return publicKey
}

function jsonResponse (status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  })
}

async function limitsResponse () {
  return jsonResponse(200, {
    status: 'success',
    maxBlobBytes: 200 * 1024 * 1024,
    maxBodyBytes: 200 * 1024 * 1024,
    serverIdentityKey: await serverIdentityKey()
  })
}

test('a JSON error envelope surfaces as BackupHttpError with status and code', async () => {
  const fakeFetch = async (url) => {
    if (url.endsWith('/v1/limits')) return await limitsResponse()
    return jsonResponse(409, {
      status: 'error',
      code: ERR_SEQ_CONFLICT,
      description: 'Sequence 5 is not head+1.'
    })
  }
  const client = new BackupCacheClient({ baseUrl: 'https://cache.example', wallet, fetch: fakeFetch })

  await assert.rejects(
    client.append('device1', 1, 5, undefined, new Uint8Array([1, 2, 3])),
    (e) => {
      assert.ok(e instanceof BackupHttpError)
      assert.equal(e.status, 409)
      assert.equal(e.code, ERR_SEQ_CONFLICT)
      assert.match(e.message, /ERR_SEQ_CONFLICT/)
      return true
    }
  )
})

test('a non-JSON error body still yields a BackupHttpError from the status alone', async () => {
  const fakeFetch = async (url) => {
    if (url.endsWith('/v1/limits')) return await limitsResponse()
    return new Response('gateway exploded', { status: 502, statusText: 'Bad Gateway' })
  }
  const client = new BackupCacheClient({ baseUrl: 'https://cache.example', wallet, fetch: fakeFetch })

  await assert.rejects(
    client.manifest(),
    (e) => e instanceof BackupHttpError && e.status === 502 && e.code === 'ERR_UNKNOWN'
  )
})

test('the signed action matches the fetched URI byte for byte, digest included', async () => {
  const seen = []
  const fakeFetch = async (url, init) => {
    if (url.endsWith('/v1/limits')) return await limitsResponse()
    seen.push({ url, init })
    return jsonResponse(201, { status: 'success', seq: 2, sha256: 'ab'.repeat(32), size: 3 })
  }
  const client = new BackupCacheClient({ baseUrl: 'https://cache.example/', wallet, fetch: fakeFetch })

  const body = new Uint8Array([1, 2, 3])
  const result = await client.append('device1', 7, 2, 'cd'.repeat(32), body)
  assert.deepEqual(result, { seq: 2, sha256: 'ab'.repeat(32), size: 3 })

  const { url, init } = seen[0]
  assert.equal(init.method, 'POST')
  assert.equal(init.headers['Content-Type'], 'application/octet-stream')
  // The trailing slash on baseUrl must not have doubled the path separator.
  assert.ok(url.startsWith('https://cache.example/v1/'))

  const wire = JSON.parse(Buffer.from(init.headers['X-Bsv-Auth'], 'base64').toString('utf8'))
  const uri = url.slice('https://cache.example'.length)
  assert.equal(uri, `/v1/log/device1?seq=2&generation=7&prevSha256=${'cd'.repeat(32)}`)
  assert.equal(wire.action, `POST ${uri} sha256=${await sha256Hex(body)}`)
})

test('limits is fetched once and reused for every subsequent proof', async () => {
  let limitsCalls = 0
  const fakeFetch = async (url) => {
    if (url.endsWith('/v1/limits')) {
      limitsCalls++
      return await limitsResponse()
    }
    return jsonResponse(200, { status: 'success', devices: [] })
  }
  const client = new BackupCacheClient({ baseUrl: 'https://cache.example', wallet, fetch: fakeFetch })

  await client.limits()
  await client.manifest()
  await client.manifest()
  assert.equal(limitsCalls, 1)
})

test('a bogus 200 from /v1/limits throws ERR_BAD_LIMITS and never poisons the cache', async () => {
  // A captive portal or misrouted proxy answers 200 with the wrong document; the client
  // must refuse it, and the very next call must reach the real server unimpeded.
  let healthy = false
  const fakeFetch = async (url) => {
    if (!healthy) return jsonResponse(200, { status: 'ok' })
    if (url.endsWith('/v1/limits')) return await limitsResponse()
    return jsonResponse(200, { status: 'success', devices: [] })
  }
  const client = new BackupCacheClient({ baseUrl: 'https://cache.example', wallet, fetch: fakeFetch })

  await assert.rejects(
    client.limits(),
    (e) => {
      assert.ok(e instanceof BackupHttpError)
      assert.equal(e.status, 200)
      assert.equal(e.code, 'ERR_BAD_LIMITS')
      return true
    }
  )

  healthy = true
  const lim = await client.limits()
  assert.equal(lim.serverIdentityKey, await serverIdentityKey())
  assert.equal(lim.maxBlobBytes, 200 * 1024 * 1024)
  // The recovered limits must actually be usable for signing, proving nothing bogus stuck.
  assert.deepEqual(await client.manifest(), [])
})

test('a limits response with a malformed identity key is refused even when numbers look fine', async () => {
  const fakeFetch = async () => jsonResponse(200, {
    status: 'success',
    maxBlobBytes: 1024,
    maxBodyBytes: 1024,
    serverIdentityKey: 'not-a-compressed-pubkey'
  })
  const client = new BackupCacheClient({ baseUrl: 'https://cache.example', wallet, fetch: fakeFetch })

  await assert.rejects(
    client.limits(),
    (e) => e instanceof BackupHttpError && e.code === 'ERR_BAD_LIMITS'
  )
})

async function sha256Hex (bytes) {
  const { createHash } = await import('node:crypto')
  return createHash('sha256').update(bytes).digest('hex')
}
