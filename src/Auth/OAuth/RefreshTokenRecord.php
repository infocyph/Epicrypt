<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class RefreshTokenRecord
{
    public function __construct(
        public string $tokenId,
        public string $familyId,
        public RefreshTokenGrant $grant,
        public int $issuedAt,
        public int $idleExpiresAt,
    ) {
        if (preg_match('/\A[A-Za-z0-9_-]{32}\z/D', $this->tokenId) !== 1) {
            throw new ConfigurationException('OAuth refresh-token ID must be a 192-bit Base64URL value.');
        }
        if (preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $this->familyId) !== 1) {
            throw new ConfigurationException('OAuth refresh-token family ID must be a 256-bit Base64URL value.');
        }
        if ($this->issuedAt < 1 || $this->issuedAt >= $this->idleExpiresAt || $this->idleExpiresAt > $this->grant->expiresAt) {
            throw new ConfigurationException('OAuth refresh-token timestamps must satisfy issued-at < idle-expiration <= authorization expiration.');
        }
    }

    public static function fromClaims(RefreshTokenArtifactClaims $claims): self
    {
        return new self(
            $claims->tokenId,
            $claims->familyId,
            $claims->grant,
            $claims->issuedAt,
            $claims->idleExpiresAt,
        );
    }

    public function sameState(self $other): bool
    {
        return $this->tokenId === $other->tokenId
            && $this->familyId === $other->familyId
            && $this->issuedAt === $other->issuedAt
            && $this->idleExpiresAt === $other->idleExpiresAt
            && $this->grant->sameAuthorization($other->grant)
            && $this->grant->scopes === $other->grant->scopes;
    }
}
