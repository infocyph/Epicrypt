<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Token\Jwt\DpopProof;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\JwtReplayStoreInterface;
use Infocyph\Epicrypt\Token\Jwt\OpenIdIdTokenValidator;
use Psr\Clock\ClockInterface;

function joseProfileClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(private readonly int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
}

function joseReplayStore(): JwtReplayStoreInterface
{
    return new class implements JwtReplayStoreInterface {
        /** @var array<string, true> */
        private array $seen = [];

        public function consume(string $namespace, string $tokenId, int $expiresAt): bool
        {
            $key = $namespace."\0".$tokenId;
            if ($expiresAt < 1 || isset($this->seen[$key])) {
                return false;
            }
            $this->seen[$key] = true;

            return true;
        }

        public function isRevoked(string $namespace, string $tokenId, int $expiresAt): bool
        {
            return $expiresAt > 0 && isset($this->seen['revoked' . "\0" . $namespace . "\0" . $tokenId]);
        }
    };
}

it('validates OIDC nonce azp max age and half hashes', function () {
    $value = 'access-token';
    $digest = hash('sha256', $value, true);
    $claims = [
        'aud' => ['client', 'secondary'],
        'azp' => 'client',
        'nonce' => 'browser-nonce',
        'auth_time' => 1_700_000_000,
        'at_hash' => Base64Url::encode(substr($digest, 0, 16)),
    ];
    new OpenIdIdTokenValidator(joseProfileClock(1_700_000_100))->validate(
        $claims,
        AsymmetricJwtAlgorithm::ES256,
        'client',
        nonce: 'browser-nonce',
        accessToken: $value,
        maximumAuthenticationAge: 300,
    );
    expect(true)->toBeTrue();
});

it('issues and validates replay-safe DPoP proofs with token binding', function () {
    $pair = KeyPairGenerator::sodiumSign()->generate();
    $jwk = new Jwks()->exportOkpPublicKey($pair['public'], 'dpop-key');
    $store = new class implements JwtReplayStoreInterface {
        /** @var array<string, true> */
        private array $seen = [];

        public function consume(string $namespace, string $tokenId, int $expiresAt): bool
        {
            if ($expiresAt <= 0) {
                return false;
            }
            $key = $namespace . "\0" . $tokenId;
            if (isset($this->seen[$key])) {
                return false;
            }
            $this->seen[$key] = true;

            return true;
        }

        public function isRevoked(string $namespace, string $tokenId, int $expiresAt): bool
        {
            return $namespace === '' || $tokenId === '' || $expiresAt < 1;
        }
    };
    $dpop = new DpopProof(joseProfileClock(1_700_000_010));
    $proof = $dpop->issue(
        'post',
        'https://api.example/resource?ignored=query',
        $pair['private'],
        $jwk,
        AsymmetricJwtAlgorithm::EDDSA,
        accessToken: 'access-token',
        nonce: 'server-nonce',
        issuedAt: 1_700_000_000,
        jwtId: 'proof-1',
    );
    $verified = $dpop->verifyResult(
        $proof,
        'POST',
        'https://api.example/resource?different=query',
        AsymmetricJwtAlgorithm::EDDSA,
        $store,
        accessToken: 'access-token',
        nonce: 'server-nonce',
    );
    expect($verified['claims'])->toHaveKey('jti', 'proof-1')
        ->and($verified['keyThumbprint'])->toBe((new Jwks())->thumbprint($jwk))
        ->and($verified['publicJwk'])->toBe($jwk);
    expect(fn() => $dpop->verify(
        $proof,
        'POST',
        'https://api.example/resource',
        AsymmetricJwtAlgorithm::EDDSA,
        $store,
        accessToken: 'access-token',
        nonce: 'server-nonce',
    ))->toThrow(InvalidTokenException::class);

    $dpop->validateAccessTokenBinding(['cnf' => ['jkt' => (new Jwks())->thumbprint($jwk)]], $jwk);
});

it('validates OIDC half hashes for every supported signing hash family', function (AsymmetricJwtAlgorithm $algorithm) {
    $value = 'protocol-value';
    $digest = hash($algorithm->hashAlgorithm(), $value, true);
    $half = Base64Url::encode(substr($digest, 0, intdiv(strlen($digest), 2)));
    $claims = [
        'aud' => 'client',
        'nonce' => 'nonce',
        'auth_time' => 1_700_000_000,
        'at_hash' => $half,
        'c_hash' => $half,
        's_hash' => $half,
    ];

    new OpenIdIdTokenValidator(joseProfileClock(1_700_000_010))->validate(
        $claims,
        $algorithm,
        'client',
        nonce: 'nonce',
        accessToken: $value,
        authorizationCode: $value,
        state: $value,
        maximumAuthenticationAge: 10,
    );
    expect(true)->toBeTrue();
})->with([
    AsymmetricJwtAlgorithm::ES256,
    AsymmetricJwtAlgorithm::ES384,
    AsymmetricJwtAlgorithm::ES512,
]);

it('rejects invalid OIDC configuration and profile claims', function () {
    $validator = new OpenIdIdTokenValidator(joseProfileClock(1_700_000_100));
    $claims = ['aud' => ['client', 'secondary'], 'azp' => 'client', 'auth_time' => 1_700_000_000];

    expect(fn () => $validator->validate($claims, AsymmetricJwtAlgorithm::ES256, ''))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $validator->validate($claims, AsymmetricJwtAlgorithm::ES256, 'client', maximumAuthenticationAge: -1))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $validator->validate($claims, AsymmetricJwtAlgorithm::ES256, 'client', nonce: 'required'))
        ->toThrow(InvalidClaimException::class)
        ->and(fn () => $validator->validate(array_replace($claims, ['azp' => 'other']), AsymmetricJwtAlgorithm::ES256, 'client'))
        ->toThrow(InvalidClaimException::class)
        ->and(fn () => $validator->validate(array_replace($claims, ['auth_time' => 1_700_000_101]), AsymmetricJwtAlgorithm::ES256, 'client', maximumAuthenticationAge: 300))
        ->toThrow(InvalidClaimException::class)
        ->and(fn () => $validator->validate($claims, AsymmetricJwtAlgorithm::ES256, 'client', maximumAuthenticationAge: 99))
        ->toThrow(InvalidClaimException::class)
        ->and(fn () => $validator->validate(['aud' => ['client', 'client'], 'azp' => 'client'], AsymmetricJwtAlgorithm::ES256, 'client'))
        ->toThrow(InvalidClaimException::class)
        ->and(fn () => $validator->validate(['aud' => array_fill(0, 33, 'aud')], AsymmetricJwtAlgorithm::ES256, 'client'))
        ->toThrow(InvalidClaimException::class)
        ->and(fn () => $validator->validate(['aud' => str_repeat('a', 2049)], AsymmetricJwtAlgorithm::ES256, 'client'))
        ->toThrow(InvalidClaimException::class)
        ->and(fn () => $validator->validate(['aud' => 'client'], AsymmetricJwtAlgorithm::ES256, 'client', nonce: str_repeat('n', 257)))
        ->toThrow(ConfigurationException::class);
});

it('bounds DPoP configuration identifiers age and parser work', function () {
    $pair = KeyPairGenerator::sodiumSign()->generate();
    $jwks = new Jwks();
    $public = $jwks->exportOkpPublicKey($pair['public'], 'dpop');
    $private = $jwks->exportOkpPrivateKey($pair['private'], 'dpop');
    $dpop = new DpopProof(joseProfileClock(1_700_000_000));

    expect(fn () => $dpop->issue("GET\nPOST", 'https://api.example/resource', $pair['private'], $public, AsymmetricJwtAlgorithm::EDDSA))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $dpop->issue('GET', 'file:///tmp/value', $pair['private'], $public, AsymmetricJwtAlgorithm::EDDSA))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $dpop->issue('GET', 'https://api.example/resource', $pair['private'], $private, AsymmetricJwtAlgorithm::EDDSA))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $dpop->issue('GET', 'https://api.example/resource', $pair['private'], $public, AsymmetricJwtAlgorithm::EDDSA, jwtId: ''))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $dpop->issue('GET', 'https://api.example/resource', $pair['private'], $public, AsymmetricJwtAlgorithm::EDDSA, nonce: str_repeat('n', 257)))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $dpop->verify(str_repeat('x', 16_385), 'GET', 'https://api.example/resource', AsymmetricJwtAlgorithm::EDDSA, joseReplayStore()))
        ->toThrow(InvalidTokenException::class);

    $old = $dpop->issue(
        'GET',
        'https://api.example/resource',
        $pair['private'],
        $public,
        AsymmetricJwtAlgorithm::EDDSA,
        issuedAt: 1_699_999_699,
    );
    $future = $dpop->issue(
        'GET',
        'https://api.example/resource',
        $pair['private'],
        $public,
        AsymmetricJwtAlgorithm::EDDSA,
        issuedAt: 1_700_000_006,
        jwtId: 'future-proof',
    );
    $futureBoundary = $dpop->issue(
        'GET',
        'https://api.example/resource',
        $pair['private'],
        $public,
        AsymmetricJwtAlgorithm::EDDSA,
        issuedAt: 1_700_000_005,
        jwtId: 'future-boundary',
    );

    expect(fn () => $dpop->verify($old, 'GET', 'https://api.example/resource', AsymmetricJwtAlgorithm::EDDSA, joseReplayStore()))
        ->toThrow(InvalidTokenException::class)
        ->and(fn () => $dpop->verify($old, 'GET', 'https://api.example/resource', AsymmetricJwtAlgorithm::EDDSA, joseReplayStore(), maximumAgeSeconds: 0))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $dpop->verify($future, 'GET', 'https://api.example/resource', AsymmetricJwtAlgorithm::EDDSA, joseReplayStore()))
        ->toThrow(InvalidTokenException::class)
        ->and(fn () => $dpop->verify($futureBoundary, 'GET', 'https://api.example/resource', AsymmetricJwtAlgorithm::EDDSA, joseReplayStore(), maximumFutureSkewSeconds: 301))
        ->toThrow(ConfigurationException::class);

    expect($dpop->verify(
        $futureBoundary,
        'GET',
        'https://api.example/resource',
        AsymmetricJwtAlgorithm::EDDSA,
        joseReplayStore(),
    ))->toHaveKey('jti', 'future-boundary');
});
