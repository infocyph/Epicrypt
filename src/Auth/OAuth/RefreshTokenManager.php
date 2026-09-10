<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
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

    public function inspect(#[\SensitiveParameter] string $token): RefreshTokenInspectionResult
    {
        try {
            $claims = $this->artifact->decryptForStateResolution($token);
        } catch (InvalidTokenException) {
            return RefreshTokenInspectionResult::of(RefreshTokenInspectionStatus::INVALID);
        }

        $record = RefreshTokenRecord::fromClaims($claims);

        return RefreshTokenInspectionResult::of(
            $this->store->inspect($record, $this->clock->now()->getTimestamp()),
            $record,
        );
    }

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
        AuthProtocolPolicy::assertText(
            $authorizationId,
            AuthProtocolPolicy::MAX_IDENTIFIER_BYTES,
            'Refresh-token authorization ID',
        );

        return $this->store->revokeAuthorization($authorizationId, $this->clock->now()->getTimestamp());
    }

    public function revokeForClient(#[\SensitiveParameter] string $token, string $clientId): bool
    {
        AuthProtocolPolicy::assertText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Refresh-token client ID');
        $inspection = $this->inspect($token);
        $record = $inspection->record;
        if (!$record instanceof RefreshTokenRecord || !hash_equals($record->grant->clientId, $clientId)) {
            return false;
        }

        return $this->store->revokeFamily($record->tokenId, $this->clock->now()->getTimestamp());
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
        AuthProtocolPolicy::assertText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Refresh-token client ID');
        $this->assertDpopKeyThumbprint($dpopKeyThumbprint);

        try {
            $currentClaims = $this->artifact->decryptForStateResolution($token);
        } catch (InvalidTokenException) {
            return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::INVALID);
        }

        $current = RefreshTokenRecord::fromClaims($currentClaims);
        $successorGrant = $this->successorGrant($current, $requestedScopes);
        if (!$successorGrant instanceof RefreshTokenGrant) {
            return RefreshTokenRotationResult::failure(RefreshTokenRotationStatus::SCOPE_MISMATCH);
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

    private function assertDpopKeyThumbprint(?string $dpopKeyThumbprint): void
    {
        if ($dpopKeyThumbprint !== null && !RefreshTokenGrant::validDpopKeyThumbprint($dpopKeyThumbprint)) {
            throw new ConfigurationException('Refresh-token DPoP key thumbprint must be a SHA-256 Base64URL value.');
        }
    }

    /**
     * @param null|array<array-key, mixed> $requestedScopes
     */
    private function successorGrant(RefreshTokenRecord $current, ?array $requestedScopes): ?RefreshTokenGrant
    {
        if ($requestedScopes === null) {
            return $current->grant;
        }

        try {
            return $current->grant->withScopes($requestedScopes);
        } catch (ConfigurationException) {
            return null;
        }
    }
}
