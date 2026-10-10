<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\DpopProof;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtFailureReason;
use Infocyph\Epicrypt\Token\Jwt\JwtReplayMode;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\JwtReplayStoreInterface;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use Psr\Clock\ClockInterface;

function replayBoundaryClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(public int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
}

function expiringReplayStore(ClockInterface $clock): JwtReplayStoreInterface
{
    return new class($clock) implements JwtReplayStoreInterface {
        /** @var array<string, int> */
        private array $expirations = [];

        public function __construct(private ClockInterface $clock) {}

        public function consume(string $namespace, string $tokenId, int $expiresAt): bool
        {
            $now = $this->clock->now()->getTimestamp();
            $key = $namespace . "\0" . $tokenId;
            if (($this->expirations[$key] ?? 0) > $now) {
                return false;
            }
            if ($expiresAt <= $now) {
                return false;
            }
            $this->expirations[$key] = $expiresAt;

            return true;
        }

        public function isRevoked(string $namespace, string $tokenId, int $expiresAt): bool
        {
            return false;
        }
    };
}

it('retains single-use JWT state through leeway for symmetric and EdDSA verifiers', function (bool $asymmetric) {
    $clock = replayBoundaryClock(1000);
    $store = expiringReplayStore($clock);
    $policy = JwtPolicy::passwordReset('issuer', 'web');
    $claims = new JwtClaims('issuer', 'user', ['web'], 1010, 1000, 1000, 'replay-id');
    if ($asymmetric) {
        $pair = KeyPairGenerator::sodiumSign()->generate();
        $token = AsymmetricJwt::issuer($pair['private'], $policy->expectedType, algorithm: AsymmetricJwtAlgorithm::EDDSA)->issue($claims);
        $verifier = AsymmetricJwt::verifier($pair['public'], $policy, AsymmetricJwtAlgorithm::EDDSA, $store, $clock);
    } else {
        $key = random_bytes(64);
        $token = SymmetricJwt::issuer($key, $policy->expectedType)->issue($claims);
        $verifier = SymmetricJwt::verifier($key, $policy, replayStore: $store, clock: $clock);
    }
    expect($verifier->verify($token))->toBeTrue()
        ->and($verifier->verify($token))->toBeFalse();

    $clock->timestamp = 1011;
    expect($verifier->verify($token))->toBeFalse();
    $clock->timestamp = 1039;
    expect($verifier->verify($token))->toBeFalse();
    $clock->timestamp = 1040;
    expect($verifier->verify($token))->toBeFalse();
})->with(['symmetric' => [false], 'asymmetric' => [true]]);

it('holds DPoP replay state through the inclusive oldest accepted second', function () {
    $clock = replayBoundaryClock(1000);
    $pair = KeyPairGenerator::sodiumSign()->generate();
    $jwk = new Jwks()->exportOkpPublicKey($pair['public'], 'key-1');
    $dpop = new DpopProof($clock);
    $proof = $dpop->issue(
        'GET',
        'https://api.example/endpoint',
        $pair['private'],
        $jwk,
        AsymmetricJwtAlgorithm::EDDSA,
        issuedAt: 700,
        jwtId: 'proof-1',
    );
    $store = expiringReplayStore($clock);
    $args = [$proof, 'GET', 'https://api.example/endpoint', AsymmetricJwtAlgorithm::EDDSA, $store];
    $dpop->verify(...$args);
    expect(fn () => $dpop->verify(...$args))->toThrow(InvalidTokenException::class);
});

it('retains replay state through acceptance for single-use token policies', function (string $purpose, bool $asymmetric, int $leeway) {
    $clock = replayBoundaryClock(1000);
    $store = expiringReplayStore($clock);
    $base = match ($purpose) {
        'reset' => JwtPolicy::passwordReset('issuer', 'web'),
        'email' => JwtPolicy::emailVerification('issuer', 'web'),
        'action' => JwtPolicy::singleUseAction('issuer', 'web'),
    };
    $policy = new JwtPolicy('issuer', 'web', $base->expectedType, leewaySeconds: $leeway, replayMode: JwtReplayMode::SINGLE_USE);
    $claims = new JwtClaims('issuer', 'user', ['web'], 1010, 1000, 1000, 'replay-' . $purpose);
    if ($asymmetric) {
        $pair = KeyPairGenerator::sodiumSign()->generate();
        $token = AsymmetricJwt::issuer($pair['private'], $policy->expectedType, algorithm: AsymmetricJwtAlgorithm::EDDSA)->issue($claims);
        $verifier = AsymmetricJwt::verifier($pair['public'], $policy, AsymmetricJwtAlgorithm::EDDSA, $store, $clock);
    } else {
        $key = random_bytes(64);
        $token = SymmetricJwt::issuer($key, $policy->expectedType)->issue($claims);
        $verifier = SymmetricJwt::verifier($key, $policy, replayStore: $store, clock: $clock);
    }

    expect($verifier->verify($token))->toBeTrue()
        ->and($verifier->verifyResult($token)->failureReason)->toBe(JwtFailureReason::REPLAYED);
    $clock->timestamp = 1009 + $leeway;
    expect($verifier->verifyResult($token)->failureReason)->toBe(JwtFailureReason::REPLAYED);
    $clock->timestamp = 1010 + $leeway;
    expect($verifier->verifyResult($token)->failureReason)->toBe(JwtFailureReason::EXPIRED);
})->with([
    'symmetric reset no leeway' => ['reset', false, 0],
    'symmetric email leeway' => ['email', false, 30],
    'symmetric action leeway' => ['action', false, 30],
    'asymmetric reset leeway' => ['reset', true, 30],
    'asymmetric email no leeway' => ['email', true, 0],
    'asymmetric action leeway' => ['action', true, 30],
]);

it('does not consume replay state for rejected JWT signatures or claims', function () {
    $clock = replayBoundaryClock(1000);
    $store = new class implements JwtReplayStoreInterface {
        public int $attempts = 0;

        public function consume(string $namespace, string $tokenId, int $expiresAt): bool
        {
            $this->attempts++;

            return $this->attempts === 1;
        }

        public function isRevoked(string $namespace, string $tokenId, int $expiresAt): bool
        {
            return false;
        }
    };
    $key = random_bytes(64);
    $policy = JwtPolicy::passwordReset('issuer', 'web');
    $verifier = SymmetricJwt::verifier($key, $policy, replayStore: $store, clock: $clock);
    $badSignature = SymmetricJwt::issuer(random_bytes(64), $policy->expectedType)
        ->issue(new JwtClaims('issuer', 'user', ['web'], 1010, 1000, 1000, 'bad-signature'));
    $badIssuer = SymmetricJwt::issuer($key, $policy->expectedType)
        ->issue(new JwtClaims('other', 'user', ['web'], 1010, 1000, 1000, 'bad-issuer'));
    expect($verifier->verify($badSignature))->toBeFalse()
        ->and($verifier->verify($badIssuer))->toBeFalse()
        ->and($store->attempts)->toBe(0);

    $valid = SymmetricJwt::issuer($key, $policy->expectedType)
        ->issue(new JwtClaims('issuer', 'user', ['web'], 1010, 1000, 1000, 'valid'));
    expect($verifier->verify($valid))->toBeTrue()
        ->and($store->attempts)->toBe(1);
});

it('saturates single-use retention at the maximum integer expiry', function () {
    $clock = replayBoundaryClock(1000);
    $store = new class implements JwtReplayStoreInterface {
        public ?int $deadline = null;

        public function consume(string $namespace, string $tokenId, int $expiresAt): bool
        {
            $this->deadline = $expiresAt;

            return true;
        }

        public function isRevoked(string $namespace, string $tokenId, int $expiresAt): bool
        {
            return false;
        }
    };
    $policy = new JwtPolicy(
        'issuer',
        'web',
        'password-reset+jwt',
        maximumLifetimeSeconds: PHP_INT_MAX,
        leewaySeconds: PHP_INT_MAX,
        replayMode: JwtReplayMode::SINGLE_USE,
    );
    $key = random_bytes(64);
    $claims = new JwtClaims('issuer', 'user', ['web'], PHP_INT_MAX, 1000, 1000, 'max-expiry');
    $token = SymmetricJwt::issuer($key, $policy->expectedType)->issue($claims);
    expect(SymmetricJwt::verifier($key, $policy, replayStore: $store, clock: $clock)->verify($token))->toBeTrue()
        ->and($store->deadline)->toBe(PHP_INT_MAX);
});
