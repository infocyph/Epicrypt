<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Payload;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\NotYetValidTokenException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedTokenFormatException;
use Infocyph\Epicrypt\Exception\Token\WrongTokenContextException;
use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
use Infocyph\Epicrypt\Internal\SignedPayloadCodec;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Psr\Clock\ClockInterface;

final readonly class PurposeToken
{
    private const string ALGORITHM = 'sha512';

    private const int MAX_TTL_SECONDS = 31 * 86400;

    /** @var list<string> */
    private const array RESERVED_CLAIMS = ['exp', 'iat', 'kid', 'nbf', 'purpose', 'sub', 'tid'];

    public function __construct(
        #[\SensitiveParameter]
        private string|KeyRing $keys,
        private string $purpose,
        private ?string $context = null,
        private int $ttlSeconds = 3600,
        private ClockInterface $clock = new SystemClock(),
        #[\SensitiveParameter]
        private RandomBytesGenerator $tokenIdGenerator = new RandomBytesGenerator(),
    ) {
        SecurityPolicy::assertIdentifier($this->purpose, 'Purpose token purpose');
        if ($this->context !== null) {
            SecurityPolicy::assertIdentifier($this->context, 'Purpose token context');
        }
        SecurityPolicy::assertTtl($this->ttlSeconds, self::MAX_TTL_SECONDS, 'Purpose token TTL');
        if (is_string($this->keys)) {
            SecurityPolicy::assertHmacSecret($this->keys, 'Purpose token secret');
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function issue(
        #[\SensitiveParameter]
        array $claims = [],
        ?string $subjectId = null,
        ?int $notBefore = null,
    ): string {
        $this->assertCallerClaims($claims);
        if ($subjectId !== null) {
            SecurityPolicy::assertIdentifier($subjectId, 'Purpose token subject');
        }

        $now = $this->clock->now()->getTimestamp();
        $expiresAt = $now + $this->ttlSeconds;
        if ($notBefore !== null && ($notBefore < $now || $notBefore >= $expiresAt)) {
            throw new ConfigurationException('Purpose token not-before must be between issuance and expiration.');
        }

        $payload = $claims + [
            'purpose' => $this->purpose,
            'tid' => $this->tokenIdGenerator->string(48),
        ];
        if ($subjectId !== null) {
            $payload['sub'] = $subjectId;
        }
        if ($notBefore !== null) {
            $payload['nbf'] = $notBefore;
        }

        [$key, $keyId] = $this->writeKey();
        if ($keyId !== null) {
            $payload['kid'] = $keyId;
        }

        return new SignedPayloadCodec($key, clock: $this->clock)->issue(
            $payload,
            $expiresAt,
            $this->context,
        );
    }

    public function verify(#[\SensitiveParameter] string $token): PurposeTokenVerificationResult
    {
        $selected = $this->verificationKey($token);
        if ($selected instanceof PurposeTokenVerificationResult) {
            return $selected;
        }

        [$key, $keyId, $usedFallbackKey] = $selected;
        $codec = new SignedPayloadCodec($key, clock: $this->clock);

        try {
            $payload = $codec->verify($token, $this->context);
        } catch (ExpiredTokenException) {
            return $this->temporalFailure(
                $token,
                PurposeTokenFailureReason::EXPIRED_TOKEN,
                $keyId,
                $usedFallbackKey,
            );
        } catch (NotYetValidTokenException) {
            return $this->temporalFailure(
                $token,
                PurposeTokenFailureReason::NOT_YET_VALID,
                $keyId,
                $usedFallbackKey,
            );
        } catch (WrongTokenContextException) {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::WRONG_CONTEXT);
        } catch (UnsupportedTokenFormatException) {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::UNSUPPORTED_FORMAT);
        } catch (TokenException|ConfigurationException|\JsonException) {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::INVALID_TOKEN);
        }

        return $this->verifiedResult($payload, $keyId, $usedFallbackKey);
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function assertCallerClaims(#[\SensitiveParameter] array $claims): void
    {
        foreach (self::RESERVED_CLAIMS as $name) {
            if (array_key_exists($name, $claims)) {
                throw new ConfigurationException(sprintf('Purpose token claim "%s" is reserved.', $name));
            }
        }
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    private function callerClaims(#[\SensitiveParameter] array $payload): array
    {
        foreach (self::RESERVED_CLAIMS as $name) {
            unset($payload[$name]);
        }

        return $payload;
    }

    /** @param array<string, mixed> $payload */
    private function integerClaim(#[\SensitiveParameter] array $payload, string $name, bool $required): ?int
    {
        if (!array_key_exists($name, $payload)) {
            return $required ? throw new InvalidTokenException(sprintf('Purpose token requires %s.', $name)) : null;
        }
        if (!is_int($payload[$name])) {
            throw new InvalidTokenException(sprintf('Purpose token %s must be an integer.', $name));
        }

        return $payload[$name];
    }

    /**
     * @param array<string, mixed> $payload
     * @return array{subject_id: ?string, token_id: string, issued_at: int, not_before: ?int, expires_at: int}
     */
    private function metadata(#[\SensitiveParameter] array $payload): array
    {
        $tokenId = $payload['tid'] ?? null;
        if (!is_string($tokenId) || preg_match('/\A[A-Za-z0-9_-]{16,128}\z/D', $tokenId) !== 1) {
            throw new InvalidTokenException('Purpose token requires a valid token id.');
        }
        $subjectId = $payload['sub'] ?? null;
        if ($subjectId !== null) {
            if (!is_string($subjectId)) {
                throw new InvalidTokenException('Purpose token subject must be a string.');
            }

            try {
                SecurityPolicy::assertIdentifier($subjectId, 'Purpose token subject');
            } catch (ConfigurationException $exception) {
                throw new InvalidTokenException('Purpose token subject is invalid.', 0, $exception);
            }
        }

        $issuedAt = $this->integerClaim($payload, 'iat', true);
        $expiresAt = $this->integerClaim($payload, 'exp', true);
        if ($issuedAt === null || $expiresAt === null) {
            throw new InvalidTokenException('Purpose token temporal metadata is incomplete.');
        }

        return [
            'subject_id' => $subjectId,
            'token_id' => $tokenId,
            'issued_at' => $issuedAt,
            'not_before' => $this->integerClaim($payload, 'nbf', false),
            'expires_at' => $expiresAt,
        ];
    }

    private function temporalFailure(
        #[\SensitiveParameter]
        string $token,
        PurposeTokenFailureReason $reason,
        ?string $keyId,
        bool $usedFallbackKey,
    ): PurposeTokenVerificationResult {
        try {
            $payload = SignedPayloadCodec::unverifiedPayload($token);
            $purpose = $payload['purpose'] ?? null;
            if (!is_string($purpose) || $purpose === '') {
                return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::INVALID_TOKEN);
            }
            if (!hash_equals($this->purpose, $purpose)) {
                return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::WRONG_PURPOSE);
            }
            $metadata = $this->metadata($payload);
        } catch (\Throwable) {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::INVALID_TOKEN);
        }

        return new PurposeTokenVerificationResult(
            verified: false,
            failureReason: $reason,
            subjectId: $metadata['subject_id'],
            tokenId: $metadata['token_id'],
            issuedAt: $metadata['issued_at'],
            notBefore: $metadata['not_before'],
            expiresAt: $metadata['expires_at'],
            matchedKeyId: $keyId,
            usedFallbackKey: $usedFallbackKey,
        );
    }

    /**
     * @return array{string, ?string, bool}|PurposeTokenVerificationResult
     */
    private function verificationKey(#[\SensitiveParameter] string $token): array|PurposeTokenVerificationResult
    {
        if (is_string($this->keys)) {
            return [$this->keys, null, false];
        }

        try {
            $untrusted = SignedPayloadCodec::unverifiedPayload($token);
        } catch (\Throwable) {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::INVALID_TOKEN);
        }

        $keyId = $untrusted['kid'] ?? null;
        if (!is_string($keyId) || $keyId === '') {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::KEY_NOT_USABLE);
        }
        $entry = $this->keys->resolveForVerification(
            $keyId,
            KeyPurpose::SIGNED_PAYLOAD,
            self::ALGORITHM,
        );
        if (!$entry instanceof KeyRingEntry) {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::KEY_NOT_USABLE);
        }
        SecurityPolicy::assertHmacSecret($entry->key, 'Purpose token key');

        return [$entry->key, $entry->id, $entry->status === KeyStatus::FALLBACK];
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function verifiedResult(
        #[\SensitiveParameter]
        array $payload,
        ?string $keyId,
        bool $usedFallbackKey,
    ): PurposeTokenVerificationResult {
        $purpose = $payload['purpose'] ?? null;
        if (!is_string($purpose) || $purpose === '') {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::INVALID_TOKEN);
        }
        if (!hash_equals($this->purpose, $purpose)) {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::WRONG_PURPOSE);
        }

        try {
            $metadata = $this->metadata($payload);
        } catch (TokenException) {
            return new PurposeTokenVerificationResult(false, PurposeTokenFailureReason::INVALID_TOKEN);
        }

        return new PurposeTokenVerificationResult(
            verified: true,
            claims: $this->callerClaims($payload),
            subjectId: $metadata['subject_id'],
            tokenId: $metadata['token_id'],
            issuedAt: $metadata['issued_at'],
            notBefore: $metadata['not_before'],
            expiresAt: $metadata['expires_at'],
            matchedKeyId: $keyId,
            usedFallbackKey: $usedFallbackKey,
        );
    }

    /**
     * @return array{string, ?string}
     */
    private function writeKey(): array
    {
        if (is_string($this->keys)) {
            return [$this->keys, null];
        }

        $entry = $this->keys->activeForWrite(KeyPurpose::SIGNED_PAYLOAD, self::ALGORITHM);
        SecurityPolicy::assertHmacSecret($entry->key, 'Purpose token key');

        return [$entry->key, $entry->id];
    }
}
