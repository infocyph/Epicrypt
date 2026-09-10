<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCode;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdIdTokenIssuer;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdSubjectIdentifierProviderInterface;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\OpenIdIdTokenValidator;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

const AUTH_INTEROP_ISSUER = 'https://interop.example.test';
const AUTH_INTEROP_AUDIENCE = 'https://api.interop.example.test';
const AUTH_INTEROP_CLIENT = 'interop-client';
const AUTH_INTEROP_NONCE = 'interop-nonce';
const AUTH_INTEROP_CODE = 'interop-authorization-code';
const AUTH_INTEROP_STATE = 'interop-state';
const AUTH_INTEROP_KID = 'interop-ps256';

/** @param array<string, mixed> $document */
function writeAuthDocument(string $path, array $document): void
{
    $json = json_encode($document, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    if (file_put_contents($path, $json . "\n") === false || !chmod($path, 0600)) {
        throw new RuntimeException('Unable to write authentication interoperability document.');
    }
}

/** @return array<string, mixed> */
function readAuthDocument(string $path): array
{
    $json = file_get_contents($path);
    if ($json === false) {
        throw new RuntimeException('Unable to read authentication interoperability document.');
    }
    $document = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
    if (!is_array($document)) {
        throw new RuntimeException('Authentication interoperability document must be an object.');
    }

    return $document;
}

/** @return array<string, mixed> */
function produceAuthFixtures(): array
{
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $jwks = new Jwks();
    $algorithm = AsymmetricJwtAlgorithm::PS256;
    $accessClaims = JwtClaims::issue(
        issuer: AUTH_INTEROP_ISSUER,
        subject: 'interop-user',
        audiences: [AUTH_INTEROP_AUDIENCE],
        ttlSeconds: 300,
        custom: [
            'client_id' => AUTH_INTEROP_CLIENT,
            'scope' => ['orders:read', 'orders:write'],
        ],
    );
    $accessToken = AsymmetricJwt::issuer(
        $pair['private'],
        type: 'at+jwt',
        keyId: AUTH_INTEROP_KID,
        algorithm: $algorithm,
    )->issue($accessClaims);

    $ring = new KeyRing([
        new KeyRingEntry(
            AUTH_INTEROP_KID,
            $pair['public'],
            KeyStatus::ACTIVE,
            KeyPurpose::OIDC_ID_TOKEN_SIGNING,
            $algorithm->value,
            issuer: AUTH_INTEROP_ISSUER,
        ),
    ]);
    $signingKeys = new AsymmetricSigningKeySet(
        issuer: AUTH_INTEROP_ISSUER,
        activeKeyId: AUTH_INTEROP_KID,
        privateKey: $pair['private'],
        publicKeys: $ring,
        algorithm: $algorithm,
        purpose: KeyPurpose::OIDC_ID_TOKEN_SIGNING,
    );
    $subjects = new class implements OpenIdSubjectIdentifierProviderInterface {
        public function subject(string $principalId, string $clientId): string
        {
            return hash('sha256', $clientId . "\0" . $principalId);
        }
    };
    $authorization = AuthorizationCode::issue(
        issuer: AUTH_INTEROP_ISSUER,
        authorizationId: 'interop-authorization',
        subject: 'interop-user',
        clientId: AUTH_INTEROP_CLIENT,
        redirectUri: 'https://client.interop.example.test/callback',
        pkceChallenge: str_repeat('A', 43),
        scopes: ['openid', 'profile'],
        audiences: [AUTH_INTEROP_AUDIENCE],
        nonce: AUTH_INTEROP_NONCE,
        authenticationTime: time() - 10,
        authenticationContext: 'urn:interop:loa2',
        authenticationMethods: ['pwd', 'otp'],
    );
    $idToken = new OpenIdIdTokenIssuer($signingKeys, $subjects)->issue(
        $authorization,
        accessToken: $accessToken,
        authorizationCode: AUTH_INTEROP_CODE,
        state: AUTH_INTEROP_STATE,
    )->token;

    return [
        'profile' => [
            'issuer' => AUTH_INTEROP_ISSUER,
            'audience' => AUTH_INTEROP_AUDIENCE,
            'client_id' => AUTH_INTEROP_CLIENT,
            'nonce' => AUTH_INTEROP_NONCE,
            'authorization_code' => AUTH_INTEROP_CODE,
            'state' => AUTH_INTEROP_STATE,
            'kid' => AUTH_INTEROP_KID,
            'algorithm' => $algorithm->value,
        ],
        'keys' => [
            'public_pem' => $pair['public'],
            'public_jwk' => $jwks->exportPublicKeyToJwk($pair['public'], AUTH_INTEROP_KID, $algorithm),
            'private_jwk' => $jwks->exportPrivateKeyToJwk($pair['private'], AUTH_INTEROP_KID, $algorithm),
        ],
        'epicrypt' => [
            'access_token' => $accessToken,
            'id_token' => $idToken,
        ],
    ];
}

/** @param array<string, mixed> $fixtures @param array<string, mixed> $candidate */
function consumeIndependentAuthFixtures(array $fixtures, array $candidate): void
{
    $profile = $fixtures['profile'] ?? null;
    $keys = $fixtures['keys'] ?? null;
    if (!is_array($profile) || !is_array($keys) || !is_string($keys['public_pem'] ?? null)) {
        throw new RuntimeException('Authentication interoperability fixture profile is invalid.');
    }

    $algorithm = AsymmetricJwtAlgorithm::from((string) $profile['algorithm']);
    $accessToken = $candidate['access_token'] ?? null;
    $idToken = $candidate['id_token'] ?? null;
    if (!is_string($accessToken) || !is_string($idToken)) {
        throw new RuntimeException('Independent authentication tokens are missing.');
    }

    $accessResult = AsymmetricJwt::verifier(
        $keys['public_pem'],
        JwtPolicy::oauthAccessToken((string) $profile['issuer'], (string) $profile['audience']),
        $algorithm,
    )->verifyResult($accessToken);
    if (!$accessResult->valid
        || ($accessResult->claims['client_id'] ?? null) !== $profile['client_id']
        || ($accessResult->claims['scope'] ?? null) !== 'orders:read orders:write') {
        throw new RuntimeException('Independent RFC 9068 access token was rejected by Epicrypt.');
    }

    $idResult = AsymmetricJwt::verifier(
        $keys['public_pem'],
        JwtPolicy::openIdIdToken((string) $profile['issuer'], (string) $profile['client_id']),
        $algorithm,
    )->verifyResult($idToken);
    if (!$idResult->valid) {
        throw new RuntimeException('Independent OIDC ID token baseline validation failed.');
    }
    new OpenIdIdTokenValidator()->validate(
        claims: $idResult->claims,
        signingAlgorithm: $algorithm,
        clientId: (string) $profile['client_id'],
        nonce: (string) $profile['nonce'],
        accessToken: $accessToken,
        authorizationCode: (string) $profile['authorization_code'],
        state: (string) $profile['state'],
        maximumAuthenticationAge: 300,
    );
}

$operation = $argv[1] ?? '';
if ($operation === 'produce' && isset($argv[2])) {
    writeAuthDocument($argv[2], produceAuthFixtures());
    fwrite(STDOUT, "Epicrypt OAuth/OIDC fixtures generated.\n");
} elseif ($operation === 'consume' && isset($argv[2], $argv[3])) {
    consumeIndependentAuthFixtures(readAuthDocument($argv[2]), readAuthDocument($argv[3]));
    fwrite(STDOUT, "Independent OAuth/OIDC fixtures accepted by Epicrypt.\n");
} else {
    throw new InvalidArgumentException(
        'Usage: php tests/Interop/auth-epicrypt.php produce <output> | consume <fixtures> <candidate>',
    );
}
