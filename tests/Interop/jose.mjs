import {
  CompactEncrypt,
  CompactSign,
  FlattenedEncrypt,
  FlattenedSign,
  GeneralEncrypt,
  GeneralSign,
  base64url,
  compactDecrypt,
  compactVerify,
  flattenedDecrypt,
  flattenedVerify,
  generalDecrypt,
  generalVerify,
  importJWK,
  importPKCS8,
  importSPKI,
} from 'jose'
import { readFile, writeFile } from 'node:fs/promises'

const [inputPath, outputPath] = process.argv.slice(2)
if (inputPath === undefined || outputPath === undefined) {
  throw new Error('Usage: node tests/Interop/jose.mjs <fixtures> <output>')
}

const fixtures = JSON.parse(await readFile(inputPath, 'utf8'))
const payload = new TextEncoder().encode(fixtures.payload)
const text = value => new TextDecoder().decode(value)

const symmetricAlgorithms = ['HS256', 'HS384', 'HS512']
const asymmetricAlgorithms = [
  'RS256', 'RS384', 'RS512',
  'PS256', 'PS384', 'PS512',
  'ES256', 'ES384', 'ES512',
  'EdDSA',
]
const jweAlgorithms = ['dir', 'A256KW', 'A256GCMKW', 'RSA-OAEP-256', 'ECDH-ES', 'ECDH-ES+A256KW']
const generalJweAlgorithms = ['A256KW', 'A256GCMKW', 'RSA-OAEP-256', 'ECDH-ES+A256KW']

async function signingKey(algorithm, privateKey) {
  if (algorithm.startsWith('HS')) {
    return base64url.decode(fixtures.keys.hmac[algorithm])
  }
  if (algorithm === 'EdDSA') {
    return importJWK(fixtures.keys.ed25519[privateKey ? 'private_jwk' : 'public_jwk'], algorithm)
  }
  if (algorithm.startsWith('ES')) {
    return privateKey
      ? importPKCS8(fixtures.keys.ec[algorithm].private, algorithm)
      : importSPKI(fixtures.keys.ec[algorithm].public, algorithm)
  }
  return privateKey
    ? importPKCS8(fixtures.keys.rsa.private, algorithm)
    : importSPKI(fixtures.keys.rsa.public, algorithm)
}

async function encryptionKey(algorithm, privateKey) {
  if (['dir', 'A256KW', 'A256GCMKW'].includes(algorithm)) {
    return base64url.decode(fixtures.keys.jwe[algorithm])
  }
  if (algorithm === 'RSA-OAEP-256') {
    return privateKey
      ? importPKCS8(fixtures.keys.rsa.private, algorithm)
      : importSPKI(fixtures.keys.rsa.public, algorithm)
  }
  return importJWK(fixtures.keys.x25519[privateKey ? 'private_jwk' : 'public_jwk'], algorithm)
}

for (const algorithm of [...symmetricAlgorithms, ...asymmetricAlgorithms]) {
  const key = await signingKey(algorithm, false)
  const expected = fixtures.epicrypt.jws[algorithm]
  const compact = await compactVerify(expected.compact, key)
  const flattened = await flattenedVerify(JSON.parse(expected.flattened), key)
  if (text(compact.payload) !== fixtures.payload || text(flattened.payload) !== fixtures.payload) {
    throw new Error(`Epicrypt ${algorithm} JWS payload mismatch`)
  }
}

const epicryptGeneral = JSON.parse(fixtures.epicrypt.jws_general)
await generalVerify(epicryptGeneral, async protectedHeader => signingKey(protectedHeader.alg, false))
const epicryptDetached = JSON.parse(fixtures.epicrypt.jws_rfc7797_detached)
await flattenedVerify({ ...epicryptDetached, payload }, await signingKey('HS256', false))

for (const algorithm of jweAlgorithms) {
  try {
    const key = await encryptionKey(algorithm, true)
    const expected = fixtures.epicrypt.jwe[algorithm]
    const compact = await compactDecrypt(expected.compact, key)
    const flattened = await flattenedDecrypt(JSON.parse(expected.flattened), key)
    if (text(compact.plaintext) !== fixtures.payload || text(flattened.plaintext) !== fixtures.payload) {
      throw new Error('payload mismatch')
    }
  } catch (error) {
    throw new Error(`Epicrypt ${algorithm} JWE rejected`, { cause: error })
  }
}

for (const algorithm of generalJweAlgorithms) {
  const key = await encryptionKey(algorithm, true)
  const result = await generalDecrypt(JSON.parse(fixtures.epicrypt.jwe_general[algorithm]), key)
  if (text(result.plaintext) !== fixtures.payload) {
    throw new Error(`Epicrypt general ${algorithm} JWE payload mismatch`)
  }
}

const candidate = {
  jws: {},
  jwe: {},
  jwe_general: {},
}
for (const algorithm of [...symmetricAlgorithms, ...asymmetricAlgorithms]) {
  const key = await signingKey(algorithm, true)
  const header = { alg: algorithm, kid: `interop-${algorithm.toLowerCase()}` }
  candidate.jws[algorithm] = {
    compact: await new CompactSign(payload).setProtectedHeader(header).sign(key),
    flattened: JSON.stringify(await new FlattenedSign(payload).setProtectedHeader(header).sign(key)),
  }
}

const general = new GeneralSign(payload)
general.addSignature(await signingKey('PS256', true)).setProtectedHeader({ alg: 'PS256', kid: 'interop-ps256' })
general.addSignature(await signingKey('EdDSA', true)).setProtectedHeader({ alg: 'EdDSA', kid: 'interop-eddsa' })
candidate.jws_general = JSON.stringify(await general.sign())

const detached = await new FlattenedSign(payload)
  .setProtectedHeader({ alg: 'HS256', kid: 'interop-rfc7797', b64: false, crit: ['b64'] })
  .sign(await signingKey('HS256', true))
delete detached.payload
candidate.jws_rfc7797_detached = JSON.stringify(detached)

for (const algorithm of jweAlgorithms) {
  const key = await encryptionKey(algorithm, false)
  const header = { alg: algorithm, enc: 'A256GCM', kid: 'interop-jwe' }
  candidate.jwe[algorithm] = {
    compact: await new CompactEncrypt(payload).setProtectedHeader(header).encrypt(key),
    flattened: JSON.stringify(await new FlattenedEncrypt(payload).setProtectedHeader(header).encrypt(key)),
  }
}

for (const algorithm of generalJweAlgorithms) {
  const key = await encryptionKey(algorithm, false)
  const encryptor = new GeneralEncrypt(payload).setProtectedHeader({
    alg: algorithm,
    enc: 'A256GCM',
  })
  encryptor.addRecipient(key).setUnprotectedHeader({ kid: 'interop-recipient' })
  candidate.jwe_general[algorithm] = JSON.stringify(await encryptor.encrypt())
}

await writeFile(outputPath, `${JSON.stringify(candidate, null, 2)}\n`, { mode: 0o600 })
process.stdout.write('Epicrypt JOSE fixtures accepted; independent fixtures generated.\n')
