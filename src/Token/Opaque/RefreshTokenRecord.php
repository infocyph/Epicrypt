<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Opaque;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class RefreshTokenRecord
{
    public function __construct(
        #[\SensitiveParameter]
        public string $digest,
        public string $familyId,
        public RefreshTokenGrant $grant,
        public int $issuedAt,
        public int $idleExpiresAt,
    ) {
        if (preg_match('/\A[a-f0-9]{64}\z/D', $this->digest) !== 1) {
            throw new ConfigurationException('Refresh-token digest must be a lowercase 256-bit hexadecimal value.');
        }
        if (preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $this->familyId) !== 1) {
            throw new ConfigurationException('Refresh-token family ID must be a 256-bit Base64URL value.');
        }
        if ($this->issuedAt < 1 || $this->issuedAt >= $this->idleExpiresAt || $this->idleExpiresAt > $this->grant->expiresAt) {
            throw new ConfigurationException('Refresh-token timestamps must satisfy issued-at < idle-expiration <= grant-expiration.');
        }
    }
}
