// Generates cross-language test vectors for the @bsv/auth proof scheme as used by
// go-private-backup-cache: canonical serialization + wallet.createSignature with
// protocolID [2,'backup cache auth'], keyID = nonce, counterparty = other side.
import { serializeAuthSigData } from '@bsv/auth'
import * as pkg from '@bsv/sdk'
const { CompletedProtoWallet, PrivateKey, Utils } = pkg

const PROTOCOL = [2, 'backup cache auth']

const clientPrivHex = '1111111111111111111111111111111111111111111111111111111111111111'
const serverPrivHex = '2222222222222222222222222222222222222222222222222222222222222222'
const clientPriv = PrivateKey.fromHex(clientPrivHex)
const serverPriv = PrivateKey.fromHex(serverPrivHex)
const clientWallet = new CompletedProtoWallet(clientPriv)
const serverWallet = new CompletedProtoWallet(serverPriv)
const { publicKey: clientPub } = await clientWallet.getPublicKey({ identityKey: true })
const { publicKey: serverPub } = await serverWallet.getPublicKey({ identityKey: true })

const cases = [
  {
    name: 'bodyless GET',
    action: 'GET /v1/manifest',
    expiresAt: 1755700000000,
    nonce: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8='
  },
  {
    name: 'upload with body hash bound into action',
    action: 'POST /v1/log/0123456789abcdef0123456789abcdef?seq=1&generation=1 sha256=2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
    expiresAt: 1755700012345,
    nonce: 'Hx0cGxoZGBcWFRQTEhEQDw4NDAsKCQgHBgUEAwIBAA=='
  },
  {
    name: 'delete with query',
    action: 'DELETE /v1/generation/0123456789abcdef0123456789abcdef/3',
    expiresAt: 1755700099999,
    nonce: 'q83vASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4k='
  }
]

const out = { protocol: PROTOCOL, clientPrivHex, serverPrivHex, clientIdentityKey: clientPub, serverIdentityKey: serverPub, cases: [] }

for (const c of cases) {
  const data = { action: c.action, identityKey: clientPub, expiresAt: c.expiresAt, nonce: c.nonce }
  const canonical = serializeAuthSigData(data)
  const { signature } = await clientWallet.createSignature({
    data: canonical,
    protocolID: PROTOCOL,
    keyID: data.nonce,
    counterparty: serverPub
  })
  // Sanity: server side verifies.
  const { valid } = await serverWallet.verifySignature({
    data: canonical,
    signature,
    protocolID: PROTOCOL,
    keyID: data.nonce,
    counterparty: clientPub
  })
  if (!valid) throw new Error(`self-check failed for ${c.name}`)
  out.cases.push({
    name: c.name,
    action: c.action,
    identityKey: clientPub,
    expiresAt: c.expiresAt,
    nonce: c.nonce,
    canonicalHex: Buffer.from(canonical).toString('hex'),
    signatureBase64: Utils.toBase64(signature)
  })
}

console.log(JSON.stringify(out, null, 2))
