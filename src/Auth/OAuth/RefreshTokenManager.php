<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;

final readonly class RefreshTokenManager
{
    private const int STORAGE_ATTEMPTS = 3;

    public function __construct(
        private RefreshTokenStoreInterface $store,
        private RefreshTokenArtifact $artifact,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function issue(
        RefreshTokenGrant $grant,
        int $idleLifetimeSeconds = RefreshTokenArtifact::DEFAULT_IDLE_LIFETIME_SECONDS,
    ): string {
        for ($attempt = 0; $attempt < self::STORAGE_ATTEMPTS; $attempt++) {
            $issue = $this->artifact->issue($grant, idleLifetimeSeconds: $idleLifetimeSeconds);
            if ($this->store->create(RefreshTokenRecord::fromClaims($issue->claims))) {
                return $issue->token;
            }
        }

        throw new ConfigurationException('Unable to persist a unique OAuth refresh token.');
    }

    public function revoke(#[\SensitiveParameter] string $token): bool
    {
        try {
            $claims = $this->artifact->decryptForStateResolution($token);
        } catch (InvalidTokenException) {
            return false;
        }

        return $this->store->revokeFamily($claims->tokenId, $this->clock->now()->getTimestamp());
    }

    public function revokeAuthorization(string $authorizationId): int
    {
        self::assertIdentifier($authorizationId, 'Refresh-token authorization ID');

        return $this->store->revokeAuthorization($authorizationId, $this->clock->now()->getTimestamp());
    }

    /** @param null|array<array-key, mixed> $requestedScopes */
    public function rotate(
        #[\SensitiveParameter]
        string $token,
        string $clientId,
        ?string $dpopKeyThumbprint = null,
        int $idleLifetimeSeconds = RefreshTokenArtifact::DEFAULT_IDLE_LIFETIME_SECONDS,
        ?array $requestedScopes = null,
    ): RefreshTokenRotationResult {
        self::assertIdentifier($clientId, 'Refresh-token client ID');
        if ($dpopKeyThumbprint !== null && !RefreshTokenGrant::validDpopKeyThumbprint($dpopKeyThumbprint)) {
            throw new ConfigurationException('Refresh-token DPoP key thumbprint must be a SHA-256 Base64URL value.');
        }

        try {
            $currentClaims = $this->artifact->decryptForStateResolution($token);
        } catch (InvalidTokenException) {
            return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::INVALID);
        }

        $current = RefreshTokenRecord::fromClaims($currentClaims);
        $successorGrant = $current->grant;
        if ($requestedScopes !== null) {
            try {
                $successorGrant = $current->grant->withScopes($requestedScopes);
            } catch (ConfigurationException) {
                return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::SCOPE_MISMATCH);
            }
        }

        if ($this->clock->now()->getTimestamp() >= $current->grant->expiresAt) {
            return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::EXPIRED);
        }

        for ($attempt = 0; $attempt < self::STORAGE_ATTEMPTS; $attempt++) {
            try {
                $issue = $this->artifact->issue(
                    $successorGrant,
                    familyId: $current->familyId,
                    idleLifetimeSeconds: $idleLifetimeSeconds,
                );
            } catch (ConfigurationException $exception) {
                if ($this->clock->now()->getTimestamp() >= $current->grant->expiresAt) {
                    return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::EXPIRED);
                }

                throw $exception;
            }

            $replacement = RefreshTokenRecord::fromClaims($issue->claims);
            $status = $this->store->rotate(
                $current,
                $replacement,
                $clientId,
                $dpopKeyThumbprint,
                $replacement->issuedAt,
            );
            if ($status === RefreshTokenRotationStatus::ROTATED) {
                return RefreshTokenRotationResult::success($issue->token, $successorGrant);
            }
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
}
