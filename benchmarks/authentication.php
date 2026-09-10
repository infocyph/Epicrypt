<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCode;
use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeArtifact;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenArtifact;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenGrant;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdIdTokenIssuer;
use Infocyph\Epicrypt\Auth\Oidc\OpenIdSubjectIdentifierProviderInterface;
use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenManager;
use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenPolicy;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Security\AsymmetricSigningKeySet;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Tests\Support\InMemoryJwtReplayStore;
use Infocyph\Epicrypt\Tests\Support\InMemoryPersonalAccessTokenStore;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\DpopProof;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\OpenIdIdTokenValidator;

require dirname(__DIR__) . '/vendor/autoload.php';

const AUTH_BENCH_ISSUER = 'https://bench.example.test';
const AUTH_BENCH_AUDIENCE = 'https://api.bench.example.test';
const AUTH_BENCH_CLIENT = 'bench-client';
const AUTH_BENCH_ITERATIONS = 100;
const AUTH_MEMORY_ITERATIONS = 2_000;
const AUTH_MEMORY_MAX_GROWTH_BYTES = 2_097_152;

/** @return array{private:string,public:string} */
function authBenchEdDsaPair(): array
{
    $pair = sodium_crypto_sign_keypair();

    return [
        'private' => sodium_crypto_sign_secretkey($pair),
        'public' => sodium_crypto_sign_publickey($pair),
    ];
}

/** @param Closure(): void $operation @return array{iterations:int,total_ms:float,us_per_operation:float} */
function authBenchMeasure(int $iterations, Closure $operation): array
{
    $started = hrtime(true);
    for ($i = 0; $i < $iterations; $i++) {
        $operation();
    }
    $elapsed = hrtime(true) - $started;

    return [
        'iterations' => $iterations,
        'total_ms' => round($elapsed / 1_000_000, 3),
        'us_per_operation' => round($elapsed / $iterations / 1_000, 3),
    ];
}

$algorithm = AsymmetricJwtAlgorithm::EDDSA;
$signing = authBenchEdDsaPair();
$accessIssuer = AsymmetricJwt::issuer($signing['private'], 'at+jwt', 'access-active', $algorithm);
$accessVerifier = AsymmetricJwt::verifier(
    $signing['public'],
    JwtPolicy::oauthAccessToken(AUTH_BENCH_ISSUER, AUTH_BENCH_AUDIENCE),
    $algorithm,
);

$codeArtifact = new AuthorizationCodeArtifact(new KeyRing([
    new KeyRingEntry(
        'code-active',
        random_bytes(32),
        KeyStatus::ACTIVE,
        KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION,
        JweKeyManagementAlgorithm::DIRECT->value,
        issuer: AUTH_BENCH_ISSUER,
    ),
]), AUTH_BENCH_ISSUER);

$refreshArtifact = new RefreshTokenArtifact(new KeyRing([
    new KeyRingEntry(
        'refresh-active',
        random_bytes(32),
        KeyStatus::ACTIVE,
        KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION,
        JweKeyManagementAlgorithm::DIRECT->value,
        issuer: AUTH_BENCH_ISSUER,
    ),
]), AUTH_BENCH_ISSUER);
$refreshGrant = new RefreshTokenGrant(
    authorizationId: 'authorization-bench',
    subject: 'bench-user',
    clientId: AUTH_BENCH_CLIENT,
    audiences: [AUTH_BENCH_AUDIENCE],
    scopes: ['orders:read', 'orders:write'],
    expiresAt: time() + 86_400,
    dpopKeyThumbprint: null,
);

$dpopPair = authBenchEdDsaPair();
$dpopJwk = new Jwks()->exportOkpPublicKey($dpopPair['public'], 'dpop-bench');
$dpop = new DpopProof();
$dpopReplay = new InMemoryJwtReplayStore();

$idPair = authBenchEdDsaPair();
$idKeys = new AsymmetricSigningKeySet(
    issuer: AUTH_BENCH_ISSUER,
    activeKeyId: 'id-active',
    privateKey: $idPair['private'],
    publicKeys: new KeyRing([
        new KeyRingEntry(
            'id-active',
            $idPair['public'],
            KeyStatus::ACTIVE,
            KeyPurpose::OIDC_ID_TOKEN_SIGNING,
            $algorithm->value,
            issuer: AUTH_BENCH_ISSUER,
        ),
    ]),
    algorithm: $algorithm,
    purpose: KeyPurpose::OIDC_ID_TOKEN_SIGNING,
);
$idSubjects = new class implements OpenIdSubjectIdentifierProviderInterface {
    public function subject(string $principalId, string $clientId): string
    {
        return hash('sha256', $clientId . "\0" . $principalId);
    }
};
$idIssuer = new OpenIdIdTokenIssuer($idKeys, $idSubjects);
$idVerifier = AsymmetricJwt::verifier(
    $idPair['public'],
    JwtPolicy::openIdIdToken(AUTH_BENCH_ISSUER, AUTH_BENCH_CLIENT),
    $algorithm,
);
$idValidator = new OpenIdIdTokenValidator();

$patPair = authBenchEdDsaPair();
$patKeys = new AsymmetricSigningKeySet(
    issuer: AUTH_BENCH_ISSUER,
    activeKeyId: 'pat-active',
    privateKey: $patPair['private'],
    publicKeys: new KeyRing([
        new KeyRingEntry(
            'pat-active',
            $patPair['public'],
            KeyStatus::ACTIVE,
            KeyPurpose::API_PERSONAL_TOKEN_SIGNING,
            $algorithm->value,
            issuer: AUTH_BENCH_ISSUER,
        ),
    ]),
    algorithm: $algorithm,
    purpose: KeyPurpose::API_PERSONAL_TOKEN_SIGNING,
);
$patManager = new PersonalAccessTokenManager(
    $patKeys,
    new InMemoryPersonalAccessTokenStore(),
    new PersonalAccessTokenPolicy(AUTH_BENCH_AUDIENCE),
);
$patIssue = $patManager->issue('bench-user', 'auth-benchmark', ['orders:read']);

$fallback = authBenchEdDsaPair();
$fallbackRing = new KeyRing([
    new KeyRingEntry(
        'access-active',
        $signing['public'],
        KeyStatus::ACTIVE,
        KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING,
        $algorithm->value,
        issuer: AUTH_BENCH_ISSUER,
    ),
    new KeyRingEntry(
        'access-fallback',
        $fallback['public'],
        KeyStatus::FALLBACK,
        KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING,
        $algorithm->value,
        issuer: AUTH_BENCH_ISSUER,
    ),
]);
$fallbackVerifier = AsymmetricJwt::verifier(
    $fallbackRing,
    JwtPolicy::oauthAccessToken(AUTH_BENCH_ISSUER, AUTH_BENCH_AUDIENCE),
    $algorithm,
);
$fallbackToken = AsymmetricJwt::issuer($fallback['private'], 'at+jwt', 'access-fallback', $algorithm)->issue(
    JwtClaims::issue(
        AUTH_BENCH_ISSUER,
        'bench-user',
        [AUTH_BENCH_AUDIENCE],
        300,
        ['client_id' => AUTH_BENCH_CLIENT, 'scope' => ['orders:read']],
    ),
);
if (!$fallbackVerifier->verify($fallbackToken)) {
    throw new RuntimeException('Fallback-key verification benchmark prerequisite failed.');
}

$measurements = [];
$measurements['access_token_issue_verify'] = authBenchMeasure(AUTH_BENCH_ITERATIONS, function () use ($accessIssuer, $accessVerifier): void {
    $token = $accessIssuer->issue(JwtClaims::issue(
        AUTH_BENCH_ISSUER,
        'bench-user',
        [AUTH_BENCH_AUDIENCE],
        300,
        ['client_id' => AUTH_BENCH_CLIENT, 'scope' => ['orders:read']],
    ));
    if (!$accessVerifier->verify($token)) {
        throw new RuntimeException('Access-token benchmark verification failed.');
    }
});

$measurements['authorization_code_jwe'] = authBenchMeasure(AUTH_BENCH_ITERATIONS, function () use ($codeArtifact): void {
    $issue = $codeArtifact->issue(
        authorizationId: Base64Url::encode(random_bytes(24)),
        subject: 'bench-user',
        clientId: AUTH_BENCH_CLIENT,
        redirectUri: 'https://client.bench.example.test/callback',
        pkceChallenge: Base64Url::encode(hash('sha256', str_repeat('V', 43), true)),
        scopes: ['openid', 'orders:read'],
        audiences: [AUTH_BENCH_AUDIENCE],
        nonce: 'bench-nonce',
        authenticationTime: time() - 1,
    );
    $codeArtifact->decrypt($issue->token);
});

$measurements['refresh_token_jwe'] = authBenchMeasure(AUTH_BENCH_ITERATIONS, function () use ($refreshArtifact, $refreshGrant): void {
    $issue = $refreshArtifact->issue($refreshGrant);
    $refreshArtifact->decryptForStateResolution($issue->token);
});

$measurements['dpop_issue_verify'] = authBenchMeasure(AUTH_BENCH_ITERATIONS, function () use ($dpop, $dpopPair, $dpopJwk, $dpopReplay, $algorithm): void {
    $proof = $dpop->issue(
        'POST',
        'https://api.bench.example.test/orders',
        $dpopPair['private'],
        $dpopJwk,
        $algorithm,
        accessToken: 'bench-access-token',
        jwtId: Base64Url::encode(random_bytes(16)),
    );
    $dpop->verifyResult(
        $proof,
        'POST',
        'https://api.bench.example.test/orders',
        $algorithm,
        $dpopReplay,
        accessToken: 'bench-access-token',
    );
});

$measurements['oidc_id_token_issue_verify'] = authBenchMeasure(AUTH_BENCH_ITERATIONS, function () use ($idIssuer, $idVerifier, $idValidator, $algorithm): void {
    $code = AuthorizationCode::issue(
        issuer: AUTH_BENCH_ISSUER,
        authorizationId: Base64Url::encode(random_bytes(24)),
        subject: 'bench-user',
        clientId: AUTH_BENCH_CLIENT,
        redirectUri: 'https://client.bench.example.test/callback',
        pkceChallenge: str_repeat('A', 43),
        scopes: ['openid'],
        audiences: [AUTH_BENCH_AUDIENCE],
        nonce: 'bench-nonce',
        authenticationTime: time() - 1,
    );
    $issue = $idIssuer->issue($code, accessToken: 'bench-access-token', authorizationCode: 'bench-code');
    $verified = $idVerifier->verifyResult($issue->token);
    if (!$verified->valid) {
        throw new RuntimeException('OIDC benchmark ID-token verification failed.');
    }
    $idValidator->validate(
        $verified->claims,
        $algorithm,
        AUTH_BENCH_CLIENT,
        nonce: 'bench-nonce',
        accessToken: 'bench-access-token',
        authorizationCode: 'bench-code',
        maximumAuthenticationAge: 300,
    );
});

$measurements['pat_store_validation'] = authBenchMeasure(AUTH_BENCH_ITERATIONS, function () use ($patManager, $patIssue): void {
    if (!$patManager->verify($patIssue->token)->accepted()) {
        throw new RuntimeException('PAT benchmark validation failed.');
    }
});

$measurements['fallback_key_verification'] = authBenchMeasure(AUTH_BENCH_ITERATIONS, function () use ($fallbackVerifier, $fallbackToken): void {
    if (!$fallbackVerifier->verify($fallbackToken)) {
        throw new RuntimeException('Fallback-key benchmark verification failed.');
    }
});

for ($i = 0; $i < 100; $i++) {
    $patManager->verify($patIssue->token);
}
gc_collect_cycles();
$memoryBefore = memory_get_usage(false);
for ($i = 0; $i < AUTH_MEMORY_ITERATIONS; $i++) {
    if (!$patManager->verify($patIssue->token)->accepted()) {
        throw new RuntimeException('Persistent-worker PAT verification failed.');
    }
}
gc_collect_cycles();
$memoryAfter = memory_get_usage(false);
$memoryGrowth = max(0, $memoryAfter - $memoryBefore);
if ($memoryGrowth > AUTH_MEMORY_MAX_GROWTH_BYTES) {
    throw new RuntimeException(sprintf(
        'Persistent-worker memory grew by %d bytes, exceeding the %d-byte release guard.',
        $memoryGrowth,
        AUTH_MEMORY_MAX_GROWTH_BYTES,
    ));
}

$evidence = [
    'php' => PHP_VERSION,
    'iterations' => AUTH_BENCH_ITERATIONS,
    'measurements' => $measurements,
    'persistent_worker_memory' => [
        'iterations' => AUTH_MEMORY_ITERATIONS,
        'before_bytes' => $memoryBefore,
        'after_bytes' => $memoryAfter,
        'growth_bytes' => $memoryGrowth,
        'max_growth_bytes' => AUTH_MEMORY_MAX_GROWTH_BYTES,
    ],
];

fwrite(
    STDOUT,
    json_encode($evidence, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . PHP_EOL,
);
