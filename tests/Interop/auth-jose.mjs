import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import {
  SignJWT,
  base64url,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
} from 'jose'

const [inputPath, outputPath] = process.argv.slice(2)
if (inputPath === undefined || outputPath === undefined) {
  throw new Error('Usage: node tests/Interop/auth-jose.mjs <fixtures> <output>')
}

const fixtures = JSON.parse(await readFile(inputPath, 'utf8'))
const { profile, keys, epicrypt } = fixtures
const publicKey = await importJWK(keys.public_jwk, profile.algorithm)
const privateKey = await importJWK(keys.private_jwk, profile.algorithm)

function halfHash(value) {
  const digest = createHash('sha256').update(value).digest()
  return base64url.encode(digest.subarray(0, digest.length / 2))
}

const accessHeader = decodeProtectedHeader(epicrypt.access_token)
const accessResult = await jwtVerify(epicrypt.access_token, publicKey, {
  issuer: profile.issuer,
  audience: profile.audience,
  algorithms: [profile.algorithm],
})
if (accessHeader.typ !== 'at+jwt'
  || accessHeader.kid !== profile.kid
  || accessResult.payload.client_id !== profile.client_id
  || accessResult.payload.scope !== 'orders:read orders:write') {
  throw new Error('Epicrypt RFC 9068 access-token profile mismatch')
}

const idHeader = decodeProtectedHeader(epicrypt.id_token)
const idResult = await jwtVerify(epicrypt.id_token, publicKey, {
  issuer: profile.issuer,
  audience: profile.client_id,
  algorithms: [profile.algorithm],
})
if (idHeader.typ !== 'JWT'
  || idHeader.kid !== profile.kid
  || idResult.payload.nonce !== profile.nonce
  || idResult.payload.at_hash !== halfHash(epicrypt.access_token)
  || idResult.payload.c_hash !== halfHash(profile.authorization_code)
  || idResult.payload.s_hash !== halfHash(profile.state)) {
  throw new Error('Epicrypt OIDC ID-token profile mismatch')
}

const now = Math.floor(Date.now() / 1000)
const accessToken = await new SignJWT({
  client_id: profile.client_id,
  scope: 'orders:read orders:write',
})
  .setProtectedHeader({ alg: profile.algorithm, kid: profile.kid, typ: 'at+jwt' })
  .setIssuer(profile.issuer)
  .setSubject('independent-user')
  .setAudience(profile.audience)
  .setIssuedAt(now)
  .setExpirationTime(now + 300)
  .setJti('independent-access-jti')
  .sign(privateKey)

const idToken = await new SignJWT({
  nonce: profile.nonce,
  auth_time: now - 10,
  acr: 'urn:interop:loa2',
  amr: ['pwd', 'otp'],
  at_hash: halfHash(accessToken),
  c_hash: halfHash(profile.authorization_code),
  s_hash: halfHash(profile.state),
})
  .setProtectedHeader({ alg: profile.algorithm, kid: profile.kid, typ: 'JWT' })
  .setIssuer(profile.issuer)
  .setSubject('independent-user')
  .setAudience(profile.client_id)
  .setIssuedAt(now)
  .setExpirationTime(now + 300)
  .sign(privateKey)

await writeFile(outputPath, `${JSON.stringify({ access_token: accessToken, id_token: idToken }, null, 2)}\n`, {
  mode: 0o600,
})
process.stdout.write('Epicrypt OAuth/OIDC fixtures accepted; independent profile fixtures generated.\n')
