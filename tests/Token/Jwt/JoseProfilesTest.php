<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Token\Jwt\DpopProof;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\JwtReplayStoreInterface;
use Infocyph\Epicrypt\Token\Jwt\OpenIdIdTokenValidator;

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
    new OpenIdIdTokenValidator()->validate(
        $claims,
        AsymmetricJwtAlgorithm::ES256,
        'client',
        nonce: 'browser-nonce',
        accessToken: $value,
        maximumAuthenticationAge: 300,
        now: 1_700_000_100,
    );
    expect(true)->toBeTrue();
});

it('issues and validates replay-safe DPoP proofs with token binding', function () {
    $pair = KeyPairGenerator::sodiumSign()->generate();
    $jwk = new Jwks()->exportOkpPublicKey($pair['public'], 'dpop-key');
    $store = new class implements JwtReplayStoreInterface {
        /** @var array<string, true> */
        private array $seen = [];

        public function consume(string $issuer, string $jwtId, int $expiresAt): bool
        {
            if ($expiresAt <= 0) {
                return false;
            }
            $key = $issuer . "\0" . $jwtId;
            if (isset($this->seen[$key])) {
                return false;
            }
            $this->seen[$key] = true;

            return true;
        }
    };
    $dpop = new DpopProof();
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
    expect($dpop->verify(
        $proof,
        'POST',
        'https://api.example/resource?different=query',
        AsymmetricJwtAlgorithm::EDDSA,
        $store,
        accessToken: 'access-token',
        nonce: 'server-nonce',
        now: 1_700_000_010,
    ))->toHaveKey('jti', 'proof-1');
    expect(fn() => $dpop->verify(
        $proof,
        'POST',
        'https://api.example/resource',
        AsymmetricJwtAlgorithm::EDDSA,
        $store,
        accessToken: 'access-token',
        nonce: 'server-nonce',
        now: 1_700_000_010,
    ))->toThrow(InvalidTokenException::class);

    $dpop->validateAccessTokenBinding(['cnf' => ['jkt' => (new Jwks())->thumbprint($jwk)]], $jwk);
});
