<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class SymmetricJwt
{
    private const string ISSUER = 'issuer';

    private const string VERIFIER = 'verifier';

    private function __construct(
        private string $mode,
        #[\SensitiveParameter]
        private string|KeyRing $key,
        private SymmetricJwtAlgorithm $algorithm,
        private string $type,
        private ?string $keyId,
        private ?JwtPolicy $policy,
        private ?JwtReplayStoreInterface $replayStore,
        private ClockInterface $clock,
    ) {
        if ($this->type === '' || strlen($this->type) > 128) {
            throw new ConfigurationException('JWT type must contain between 1 and 128 bytes.');
        }
        if ($this->keyId !== null && preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $this->keyId) !== 1) {
            throw new ConfigurationException('JWT key id must be a Base64URL-safe identifier.');
        }
        if ($this->policy !== null && $this->policy->replayMode !== JwtReplayMode::NONE && $this->replayStore === null) {
            throw new ConfigurationException('A replay store is required by the selected JWT replay policy.');
        }
        if (is_string($this->key)) {
            self::assertKeySize($this->key, $this->algorithm);
        }
    }

    public static function generateBinaryKey(SymmetricJwtAlgorithm $algorithm = SymmetricJwtAlgorithm::HS512): string
    {
        return random_bytes(self::minimumKeyBytes($algorithm));
    }

    public static function generateEncodedKey(SymmetricJwtAlgorithm $algorithm = SymmetricJwtAlgorithm::HS512): string
    {
        return Base64Url::encode(self::generateBinaryKey($algorithm));
    }

    public static function issuer(
        #[\SensitiveParameter]
        string $key,
        string $type,
        ?string $keyId = null,
        SymmetricJwtAlgorithm $algorithm = SymmetricJwtAlgorithm::HS512,
        ClockInterface $clock = new SystemClock(),
    ): self {
        return new self(self::ISSUER, $key, $algorithm, $type, $keyId, null, null, $clock);
    }

    public static function verifier(
        #[\SensitiveParameter]
        string|KeyRing $key,
        JwtPolicy $policy,
        SymmetricJwtAlgorithm $algorithm = SymmetricJwtAlgorithm::HS512,
        ?JwtReplayStoreInterface $replayStore = null,
        ClockInterface $clock = new SystemClock(),
    ): self {
        return new self(self::VERIFIER, $key, $algorithm, $policy->expectedType, null, $policy, $replayStore, $clock);
    }

    public function issue(JwtClaims $claims): string
    {
        if ($this->mode !== self::ISSUER || !is_string($this->key)) {
            throw new ConfigurationException('This JWT instance is not configured for issuance.');
        }

        $header = ['alg' => $this->algorithm->value, 'typ' => $this->type];
        if ($this->keyId !== null) {
            $header['kid'] = $this->keyId;
        }
        [$encodedHeader, $encodedPayload] = JwtToken::encodeSegments($header, $claims->toArray());
        $input = $encodedHeader . '.' . $encodedPayload;
        $signature = hash_hmac($this->algorithm->hmacAlgorithm(), $input, $this->key, true);

        return $input . '.' . Base64Url::encode($signature);
    }

    public function verify(#[\SensitiveParameter] string $token): bool
    {
        return $this->verifyResult($token)->valid;
    }

    public function verifyResult(#[\SensitiveParameter] string $token): JwtVerificationResult
    {
        if ($this->mode !== self::VERIFIER || $this->policy === null) {
            throw new ConfigurationException('This JWT instance is not configured for verification.');
        }

        try {
            [$encodedHeader, $encodedPayload, $signature, $header, $claims] = JwtToken::parse($token);
        } catch (Throwable) {
            return JwtVerificationResult::failure(JwtFailureReason::MALFORMED);
        }

        $headerFailure = $this->validateHeader($header);
        if ($headerFailure !== null) {
            return JwtVerificationResult::failure($headerFailure);
        }

        [$resolvedKey, $matchedKeyId, $keyFailure] = $this->resolveKey($header['kid'] ?? null);
        if ($keyFailure !== null) {
            return JwtVerificationResult::failure($keyFailure);
        }
        if (!is_string($resolvedKey)) {
            return JwtVerificationResult::failure(JwtFailureReason::KEY_NOT_USABLE);
        }

        $expected = hash_hmac($this->algorithm->hmacAlgorithm(), $encodedHeader . '.' . $encodedPayload, $resolvedKey, true);
        if (!hash_equals($expected, $signature)) {
            return JwtVerificationResult::failure(JwtFailureReason::INVALID_SIGNATURE);
        }

        $validation = JwtValidator::validate($claims, $this->policy, $this->clock->now()->getTimestamp());
        if ($validation instanceof JwtFailureReason) {
            return JwtVerificationResult::failure($validation);
        }

        if (!$this->passesReplayPolicy($validation['issuer'], $validation['jwt_id'], $validation['expires_at'])) {
            return JwtVerificationResult::failure(JwtFailureReason::REPLAYED);
        }

        return JwtVerificationResult::success($claims, $header, $matchedKeyId);
    }

    private static function assertKeySize(#[\SensitiveParameter] string $key, SymmetricJwtAlgorithm $algorithm): void
    {
        $minimum = self::minimumKeyBytes($algorithm);
        if (strlen($key) < $minimum) {
            throw new ConfigurationException(sprintf('%s keys must contain at least %d raw bytes.', $algorithm->value, $minimum));
        }
    }

    /** @return int<1, max> */
    private static function minimumKeyBytes(SymmetricJwtAlgorithm $algorithm): int
    {
        return match ($algorithm) {
            SymmetricJwtAlgorithm::HS256 => 32,
            SymmetricJwtAlgorithm::HS384 => 48,
            SymmetricJwtAlgorithm::HS512 => 64,
        };
    }

    private function passesReplayPolicy(string $issuer, string $jwtId, int $expiresAt): bool
    {
        return match ($this->policy?->replayMode) {
            null, JwtReplayMode::NONE => true,
            JwtReplayMode::DENYLIST => $this->replayStore?->isRevoked($issuer, $jwtId, $expiresAt) === false,
            JwtReplayMode::SINGLE_USE => $this->replayStore?->consume($issuer, $jwtId, $expiresAt) === true,
        };
    }

    /** @return array{?string, ?string, ?JwtFailureReason} */
    private function resolveKey(mixed $keyId): array
    {
        if (is_string($this->key)) {
            return [$this->key, null, null];
        }
        if (!is_string($keyId) || $keyId === '') {
            return [null, null, JwtFailureReason::UNKNOWN_KEY];
        }

        $entry = $this->key->resolveForVerification(
            $keyId,
            KeyPurpose::JWT_SIGNING,
            $this->algorithm->value,
            $this->policy?->expectedIssuer,
        );
        if ($entry === null) {
            return [null, null, JwtFailureReason::UNKNOWN_KEY];
        }

        try {
            self::assertKeySize($entry->key, $this->algorithm);
        } catch (ConfigurationException) {
            return [null, null, JwtFailureReason::KEY_NOT_USABLE];
        }

        return [$entry->key, $entry->id, null];
    }

    /**
     * @param array<string, mixed> $header
     */
    private function validateHeader(array $header): ?JwtFailureReason
    {
        if (!isset($header['alg'], $header['typ']) || !is_string($header['alg']) || !is_string($header['typ'])) {
            return JwtFailureReason::MALFORMED;
        }
        if (SymmetricJwtAlgorithm::tryFrom($header['alg']) === null) {
            return JwtFailureReason::UNSUPPORTED_ALGORITHM;
        }
        if ($header['alg'] !== $this->algorithm->value) {
            return JwtFailureReason::ALGORITHM_MISMATCH;
        }
        if ($this->policy?->acceptsType($header['typ']) !== true) {
            return JwtFailureReason::INVALID_TYPE;
        }
        if (isset($header['cty']) || isset($header['crit'])) {
            return JwtFailureReason::MALFORMED;
        }
        if (isset($header['kid']) && (!is_string($header['kid']) || preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $header['kid']) !== 1)) {
            return JwtFailureReason::MALFORMED;
        }

        return null;
    }
}
