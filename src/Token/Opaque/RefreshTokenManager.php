<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Opaque;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;

final readonly class RefreshTokenManager
{
    public const int DEFAULT_IDLE_LIFETIME_SECONDS = 2_592_000;

    public const int MAXIMUM_IDLE_LIFETIME_SECONDS = 31_536_000;

    private const int STORAGE_ATTEMPTS = 3;

    public function __construct(
        private RefreshTokenStoreInterface $store,
        private OpaqueToken $tokens = new OpaqueToken(),
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function issue(
        RefreshTokenGrant $grant,
        int $idleLifetimeSeconds = self::DEFAULT_IDLE_LIFETIME_SECONDS,
    ): string {
        self::assertIdleLifetime($idleLifetimeSeconds);
        $now = $this->clock->now()->getTimestamp();
        if ($grant->expiresAt <= $now) {
            throw new ConfigurationException('Refresh-token grant expiration must be in the future.');
        }
        $familyId = Base64Url::encode(random_bytes(32));
        for ($attempt = 0; $attempt < self::STORAGE_ATTEMPTS; $attempt++) {
            $token = $this->tokens->issue();
            $record = new RefreshTokenRecord(
                $this->tokens->hash($token),
                $familyId,
                $grant,
                $now,
                min($grant->expiresAt, $now + $idleLifetimeSeconds),
            );
            if ($this->store->create($record)) {
                return $token;
            }
            sodium_memzero($token);
        }

        throw new TokenException('Unable to persist a unique refresh token.');
    }

    public function revoke(#[\SensitiveParameter] string $token): bool
    {
        if (!self::validToken($token)) {
            return false;
        }

        return $this->store->revokeFamily($this->tokens->hash($token), $this->clock->now()->getTimestamp());
    }

    public function revokeGrant(string $grantId): int
    {
        self::assertIdentifier($grantId, 'Refresh-token grant ID');

        return $this->store->revokeGrant($grantId, $this->clock->now()->getTimestamp());
    }

    /**
     * @param null|array<array-key, mixed> $requestedScopes
     */
    public function rotate(
        #[\SensitiveParameter]
        string $token,
        string $clientId,
        ?string $dpopKeyThumbprint = null,
        int $idleLifetimeSeconds = self::DEFAULT_IDLE_LIFETIME_SECONDS,
        ?array $requestedScopes = null,
    ): RefreshTokenRotationResult {
        self::assertIdentifier($clientId, 'Refresh-token client ID');
        self::assertIdleLifetime($idleLifetimeSeconds);
        if ($dpopKeyThumbprint !== null && !RefreshTokenGrant::validDpopKeyThumbprint($dpopKeyThumbprint)) {
            throw new ConfigurationException('Refresh-token DPoP key thumbprint must be a SHA-256 Base64URL value.');
        }
        $normalizedScopes = $requestedScopes === null ? null : RefreshTokenGrant::normalizeScopes($requestedScopes);
        if (!self::validToken($token)) {
            return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::INVALID);
        }

        $now = $this->clock->now()->getTimestamp();
        $currentDigest = $this->tokens->hash($token);
        for ($attempt = 0; $attempt < self::STORAGE_ATTEMPTS; $attempt++) {
            $replacement = $this->tokens->issue();
            $result = $this->store->rotate(
                $currentDigest,
                $this->tokens->hash($replacement),
                $clientId,
                $dpopKeyThumbprint,
                $normalizedScopes,
                $now,
                $idleLifetimeSeconds,
            );
            $status = $result['status'];
            $grant = $result['grant'];
            if ($status === RefreshTokenRotationStatus::ROTATED) {
                if (!$grant instanceof RefreshTokenGrant) {
                    sodium_memzero($replacement);

                    throw new TokenException('Refresh-token store returned an incomplete rotation result.');
                }

                return RefreshTokenRotationResult::success($replacement, $grant);
            }
            sodium_memzero($replacement);
            if ($status !== RefreshTokenRotationStatus::CONFLICT) {
                return RefreshTokenRotationResult::failure($status);
            }
        }

        return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::CONFLICT);
    }

    private static function assertIdentifier(string $value, string $label): void
    {
        if ($value === '' || strlen($value) > 255 || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new ConfigurationException(sprintf('%s is invalid.', $label));
        }
    }

    private static function assertIdleLifetime(int $idleLifetimeSeconds): void
    {
        if ($idleLifetimeSeconds < 1 || $idleLifetimeSeconds > self::MAXIMUM_IDLE_LIFETIME_SECONDS) {
            throw new ConfigurationException(sprintf(
                'Refresh-token idle lifetime must contain between 1 and %d seconds.',
                self::MAXIMUM_IDLE_LIFETIME_SECONDS,
            ));
        }
    }

    private static function validToken(string $token): bool
    {
        $length = strlen($token);

        return $length >= OpaqueToken::MINIMUM_LENGTH
            && $length <= OpaqueToken::MAXIMUM_LENGTH
            && preg_match('/\A[A-Za-z0-9_-]+\z/D', $token) === 1;
    }
}
