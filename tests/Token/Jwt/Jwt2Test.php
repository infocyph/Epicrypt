<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtFailureReason;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\JwtReplayStoreInterface;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use Psr\Clock\ClockInterface;

it('issues and verifies all registered JWT claims with fixed algorithm and type', function () {
    $key = random_bytes(64);
    $claims = JwtClaims::issue('https://issuer.example', 'user-7', ['api'], 300, ['roles' => ['admin']]);
    $policy = JwtPolicy::accessToken('https://issuer.example', 'api');
    $token = SymmetricJwt::issuer($key, 'at+jwt')->issue($claims);
    $result = SymmetricJwt::verifier($key, $policy)->verifyResult($token);

    expect($result->valid)->toBeTrue()
        ->and(array_keys($result->claims))->toContain('iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti');
});

it('issues and verifies every configured HS RS and ES algorithm', function () {
    $claims = JwtClaims::issue('matrix-issuer', 'subject', ['api'], 300);
    $policy = JwtPolicy::accessToken('matrix-issuer', 'api');

    foreach (SymmetricJwtAlgorithm::cases() as $algorithm) {
        $key = SymmetricJwt::generateBinaryKey($algorithm);
        $token = SymmetricJwt::issuer($key, 'at+jwt', algorithm: $algorithm)->issue($claims);
        expect(SymmetricJwt::verifier($key, $policy, $algorithm)->verify($token))->toBeTrue();
    }

    $rsa = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048)->generate();
    foreach ([
        AsymmetricJwtAlgorithm::RS256,
        AsymmetricJwtAlgorithm::RS384,
        AsymmetricJwtAlgorithm::RS512,
        AsymmetricJwtAlgorithm::PS256,
        AsymmetricJwtAlgorithm::PS384,
        AsymmetricJwtAlgorithm::PS512,
    ] as $algorithm) {
        $token = AsymmetricJwt::issuer($rsa['private'], 'at+jwt', algorithm: $algorithm)->issue($claims);
        expect(AsymmetricJwt::verifier($rsa['public'], $policy, $algorithm)->verify($token))->toBeTrue();
    }

    $curves = [
        AsymmetricJwtAlgorithm::ES256->value => OpenSslCurveName::PRIME256V1,
        AsymmetricJwtAlgorithm::ES384->value => OpenSslCurveName::SECP384R1,
        AsymmetricJwtAlgorithm::ES512->value => OpenSslCurveName::SECP521R1,
    ];
    foreach ($curves as $algorithmValue => $curve) {
        $algorithm = AsymmetricJwtAlgorithm::from($algorithmValue);
        $pair = KeyPairGenerator::openSsl(
            OpenSslRsaBits::BITS_3072,
            OpenSslKeyType::EC,
            $curve,
        )->generate();
        $token = AsymmetricJwt::issuer($pair['private'], 'at+jwt', algorithm: $algorithm)->issue($claims);
        expect(AsymmetricJwt::verifier($pair['public'], $policy, $algorithm)->verify($token))->toBeTrue();
    }

    $ed25519 = KeyPairGenerator::sodiumSign()->generate();
    $eddsa = AsymmetricJwt::issuer($ed25519['private'], 'at+jwt', algorithm: AsymmetricJwtAlgorithm::EDDSA)->issue($claims);
    expect(AsymmetricJwt::verifier($ed25519['public'], $policy, AsymmetricJwtAlgorithm::EDDSA)->verify($eddsa))->toBeTrue();
});

it('rejects weak keys, algorithm confusion, invalid type, and unknown kid', function () {
    expect(fn() => SymmetricJwt::issuer('weak', 'at+jwt'))->toThrow(ConfigurationException::class);

    $key = random_bytes(64);
    $claims = JwtClaims::issue('issuer', 'subject', ['api'], 300);
    $token = SymmetricJwt::issuer($key, 'wrong+jwt')->issue($claims);
    $policy = JwtPolicy::accessToken('issuer', 'api');
    expect(SymmetricJwt::verifier($key, $policy)->verifyResult($token)->failureReason)
        ->toBe(JwtFailureReason::INVALID_TYPE);

    $ring = new KeyRing([
        new KeyRingEntry('known', $key, KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, SymmetricJwtAlgorithm::HS512->value, issuer: 'issuer'),
    ]);
    $unknown = SymmetricJwt::issuer($key, 'at+jwt', 'unknown')->issue($claims);
    expect(SymmetricJwt::verifier($ring, $policy)->verifyResult($unknown)->failureReason)
        ->toBe(JwtFailureReason::UNKNOWN_KEY);
    $missingKid = SymmetricJwt::issuer($key, 'at+jwt')->issue($claims);
    $hs256 = SymmetricJwt::issuer($key, 'at+jwt', algorithm: SymmetricJwtAlgorithm::HS256)->issue($claims);
    expect(SymmetricJwt::verifier($ring, $policy)->verifyResult($missingKid)->failureReason)
        ->toBe(JwtFailureReason::UNKNOWN_KEY)
        ->and(SymmetricJwt::verifier($key, $policy)->verifyResult($hs256)->failureReason)
        ->toBe(JwtFailureReason::ALGORITHM_MISMATCH);
});

it('uses atomic replay consumption after successful validation', function () {
    $store = new class implements JwtReplayStoreInterface {
        /** @var array<string, true> */
        private array $consumed = [];

        public function consume(string $issuer, string $jwtId, int $expiresAt): bool
        {
            if ($expiresAt < 1) {
                return false;
            }
            $key = $issuer . ':' . $jwtId;
            if (isset($this->consumed[$key])) {
                return false;
            }
            $this->consumed[$key] = true;

            return true;
        }
    };
    $key = random_bytes(64);
    $policy = JwtPolicy::passwordReset('issuer', 'web');
    $token = SymmetricJwt::issuer($key, 'password-reset+jwt')->issue(JwtClaims::issue('issuer', 'user', ['web'], 300));
    $verifier = SymmetricJwt::verifier($key, $policy, replayStore: $store);

    expect($verifier->verify($token))->toBeTrue()
        ->and($verifier->verifyResult($token)->failureReason)->toBe(JwtFailureReason::REPLAYED);
});

it('enforces temporal boundaries and normalizes scope', function () {
    $clock = new class implements ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@2000');
        }
    };
    $key = random_bytes(64);
    $claims = new JwtClaims(
        'issuer',
        'subject',
        ['api'],
        2000,
        1900,
        1900,
        sodium_bin2base64(random_bytes(24), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
        ['scope' => 'read write'],
    );
    expect($claims->custom['scope'])->toBe('read write');

    $token = SymmetricJwt::issuer($key, 'at+jwt')->issue($claims);
    $policy = new JwtPolicy('issuer', 'api', 'at+jwt', leewaySeconds: 0);
    expect(SymmetricJwt::verifier($key, $policy, clock: $clock)->verifyResult($token)->failureReason)
        ->toBe(JwtFailureReason::EXPIRED);
});

it('supports generic JWT claim shapes and the strict OAuth access-token profile', function () {
    $key = random_bytes(64);
    $encode = static fn(string $value): string => sodium_bin2base64($value, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $sign = static function (array $claims, string $type = 'JWT') use ($key, $encode): string {
        $header = $encode(json_encode(['alg' => 'HS512', 'typ' => $type], JSON_THROW_ON_ERROR));
        $payload = $encode(json_encode($claims, JSON_THROW_ON_ERROR));

        return $header . '.' . $payload . '.' . $encode(hash_hmac('sha512', $header . '.' . $payload, $key, true));
    };
    $now = time();
    $generic = $sign(['iss' => 'issuer', 'aud' => 'api', 'exp' => (float) ($now + 300)]);

    expect(SymmetricJwt::verifier($key, JwtPolicy::generic('issuer', 'api'))->verify($generic))->toBeTrue();

    $oauthClaims = JwtClaims::issue(
        'issuer',
        'subject',
        ['api'],
        300,
        ['client_id' => 'web-client', 'scope' => ['orders:read', 'orders:write']],
    );
    $oauth = SymmetricJwt::issuer($key, 'at+jwt')->issue($oauthClaims);
    $oauthPolicy = JwtPolicy::oauthAccessToken('issuer', 'api');
    expect(SymmetricJwt::verifier($key, $oauthPolicy)->verify($oauth))->toBeTrue()
        ->and($oauthClaims->custom['scope'])->toBe('orders:read orders:write')
        ->and(SymmetricJwt::verifier($key, $oauthPolicy)->verifyResult($sign([
            'iss' => 'issuer',
            'sub' => 'subject',
            'aud' => 'api',
            'exp' => $now + 300,
            'iat' => $now,
            'jti' => 'external-token-id',
        ], 'at+jwt'))->failureReason)->toBe(JwtFailureReason::INVALID_CLIENT_ID);
});

it('returns precise failures for temporal and identity policy boundaries', function () {
    $clock = new class implements ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@2000');
        }
    };
    $key = random_bytes(64);
    $policy = new JwtPolicy('issuer', 'api', 'at+jwt', maximumLifetimeSeconds: 300, leewaySeconds: 0);
    $verifier = SymmetricJwt::verifier($key, $policy, clock: $clock);
    $jti = sodium_bin2base64(random_bytes(24), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $sign = static function (array $claims) use ($key): string {
        $header = sodium_bin2base64('{"alg":"HS512","typ":"at+jwt"}', SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
        $payload = sodium_bin2base64(
            json_encode($claims, JSON_THROW_ON_ERROR),
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
        );
        $signature = hash_hmac('sha512', $header . '.' . $payload, $key, true);

        return $header . '.' . $payload . '.' . sodium_bin2base64($signature, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    };
    $valid = ['iss' => 'issuer', 'sub' => 'subject', 'aud' => ['api'], 'exp' => 2200, 'nbf' => 1900, 'iat' => 1900, 'jti' => $jti];

    expect($verifier->verifyResult($sign(array_replace($valid, ['exp' => 2000])))->failureReason)
        ->toBe(JwtFailureReason::EXPIRED)
        ->and($verifier->verifyResult($sign(array_replace($valid, ['iat' => 2100, 'nbf' => 2100, 'exp' => 2200])))->failureReason)
        ->toBe(JwtFailureReason::ISSUED_IN_FUTURE)
        ->and($verifier->verifyResult($sign(array_replace($valid, ['nbf' => 2200, 'exp' => 2100])))->failureReason)
        ->toBe(JwtFailureReason::INVALID_LIFETIME)
        ->and($verifier->verifyResult($sign(array_replace($valid, ['exp' => 2301])))->failureReason)
        ->toBe(JwtFailureReason::INVALID_LIFETIME)
        ->and($verifier->verifyResult($sign(array_replace($valid, ['iss' => 'other'])))->failureReason)
        ->toBe(JwtFailureReason::INVALID_ISSUER)
        ->and($verifier->verifyResult($sign(array_replace($valid, ['sub' => ''])))->failureReason)
        ->toBe(JwtFailureReason::INVALID_SUBJECT)
        ->and($verifier->verifyResult($sign(array_replace($valid, ['aud' => ['other']])))->failureReason)
        ->toBe(JwtFailureReason::INVALID_AUDIENCE);
});

it('rejects malformed compact JSON and missing registered claims', function () {
    $key = random_bytes(64);
    $encode = static fn(string $value): string => sodium_bin2base64($value, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $token = static function (string $payloadJson) use ($key, $encode): string {
        $header = $encode('{"alg":"HS512","typ":"at+jwt"}');
        $payload = $encode($payloadJson);
        $signature = hash_hmac('sha512', $header . '.' . $payload, $key, true);

        return $header . '.' . $payload . '.' . $encode($signature);
    };
    $jti = sodium_bin2base64(random_bytes(24), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $now = time();
    $duplicate = sprintf(
        '{"iss":"issuer","sub":"a","sub":"b","aud":["api"],"exp":%d,"nbf":%d,"iat":%d,"jti":"%s"}',
        $now + 300,
        $now,
        $now,
        $jti,
    );
    $missing = sprintf(
        '{"iss":"issuer","sub":"a","aud":["api"],"exp":%d,"nbf":%d,"iat":%d}',
        $now + 300,
        $now,
        $now,
    );
    $invalidUtf8 = sprintf(
        "{\"iss\":\"issuer\",\"sub\":\"\xC3\x28\",\"aud\":[\"api\"],\"exp\":%d,\"nbf\":%d,\"iat\":%d,\"jti\":\"%s\"}",
        $now + 300,
        $now,
        $now,
        $jti,
    );
    $nestedDuplicate = sprintf(
        '{"iss":"issuer","sub":"a","aud":["api"],"exp":%d,"nbf":%d,"iat":%d,"jti":"%s","metadata":{"same":1,"same":2}}',
        $now + 300,
        $now,
        $now,
        $jti,
    );
    $repeatedAcrossObjects = sprintf(
        '{"iss":"issuer","sub":"a","aud":["api"],"exp":%d,"nbf":%d,"iat":%d,"jti":"%s","metadata":{"first":{"same":1},"second":{"same":2}}}',
        $now + 300,
        $now,
        $now,
        $jti,
    );
    $policy = new JwtPolicy('issuer', 'api', 'at+jwt', maximumLifetimeSeconds: 1000);
    $verifier = SymmetricJwt::verifier($key, $policy);

    expect($verifier->verifyResult($token($duplicate))->failureReason)->toBe(JwtFailureReason::MALFORMED)
        ->and($verifier->verifyResult($token($missing))->failureReason)->toBe(JwtFailureReason::INVALID_JTI)
        ->and($verifier->verifyResult($token($invalidUtf8))->failureReason)->toBe(JwtFailureReason::MALFORMED)
        ->and($verifier->verifyResult($token($nestedDuplicate))->failureReason)->toBe(JwtFailureReason::MALFORMED)
        ->and($verifier->verify($token($repeatedAcrossObjects)))->toBeTrue()
        ->and($verifier->verifyResult('not.base64url.token')->failureReason)->toBe(JwtFailureReason::MALFORMED);
});

it('rejects a deterministic compact-token parser fuzz corpus', function () {
    $verifier = SymmetricJwt::verifier(
        random_bytes(64),
        JwtPolicy::accessToken('issuer', 'api'),
    );

    for ($case = 0; $case < 128; $case++) {
        $bytes = hash('sha512', 'jwt-parser-fuzz-' . $case, true);
        $segments = [
            sodium_bin2base64(substr($bytes, 0, 13), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
            sodium_bin2base64(substr($bytes, 13, 19), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
            sodium_bin2base64(substr($bytes, 32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING),
        ];

        expect($verifier->verifyResult(implode('.', $segments))->failureReason)
            ->toBe(JwtFailureReason::MALFORMED);
    }
});

it('rejects reserved and invalid custom claims at issuance', function () {
    expect(fn() => JwtClaims::issue('issuer', 'subject', ['api'], 300, ['alg' => 'HS512']))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => JwtClaims::issue('issuer', 'subject', ['api'], 300, ['roles' => ['']]))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => JwtClaims::issue('issuer', 'subject', ['api'], 300, ['email' => 'invalid']))
        ->toThrow(ConfigurationException::class);
});
