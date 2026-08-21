import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { bodySha256Hex } from '../dist/index.js'

test('a Blob and a Uint8Array of the same content hash to the same digest', async () => {
  // Larger than one stream chunk, so the Blob path exercises incremental hashing.
  const bytes = new Uint8Array(1 << 20)
  for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251

  const fromBytes = await bodySha256Hex(bytes)
  const fromBlob = await bodySha256Hex(new Blob([bytes]))

  assert.equal(fromBytes, fromBlob)
  // Pin against an independent implementation, not just self-consistency, because this
  // digest is signed into the action string the server verifies.
  assert.equal(fromBytes, createHash('sha256').update(bytes).digest('hex'))
})

test('the digest is lowercase hex, the only casing the action string accepts', async () => {
  const digest = await bodySha256Hex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
  assert.match(digest, /^[0-9a-f]{64}$/)
})
