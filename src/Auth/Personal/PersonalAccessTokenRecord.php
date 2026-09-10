<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class PersonalAccessTokenRecord
{
    /** @var list<string> */
    public array $abilities;

    /** @param array<array-key, mixed> $abilities */
    public function __construct(
        public string $tokenId,
        public string $subject,
        public string $name,
        array $abilities,
        public int $createdAt,
        public ?int $expiresAt = null,
        public ?int $revokedAt = null,
    ) {
        if (preg_match('/\A[A-Za-z0-9_-]{32}\z/D', $this->tokenId) !== 1) {
            throw new ConfigurationException('Personal-access-token ID must be a 192-bit Base64URL value.');
        }
        AuthProtocolPolicy::assertText($this->subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Personal-access-token subject');
        AuthProtocolPolicy::assertText($this->name, AuthProtocolPolicy::MAX_PERSONAL_TOKEN_NAME_BYTES, 'Personal-access-token name');
        $this->abilities = AuthProtocolPolicy::normalizePersonalTokenAbilities($abilities);
        if ($this->createdAt < 1) {
            throw new ConfigurationException('Personal-access-token creation timestamp must be positive.');
        }
        if ($this->expiresAt !== null && $this->expiresAt <= $this->createdAt) {
            throw new ConfigurationException('Personal-access-token expiration must be after creation.');
        }
        if ($this->revokedAt !== null && $this->revokedAt < $this->createdAt) {
            throw new ConfigurationException('Personal-access-token revocation cannot predate creation.');
        }
    }

    public function isActive(int $now): bool
    {
        return $now >= $this->createdAt
            && ($this->expiresAt === null || $now < $this->expiresAt)
            && $this->revokedAt === null;
    }

    public function revoked(int $revokedAt): self
    {
        if ($this->revokedAt !== null) {
            return $this;
        }

        return new self(
            $this->tokenId,
            $this->subject,
            $this->name,
            $this->abilities,
            $this->createdAt,
            $this->expiresAt,
            $revokedAt,
        );
    }
}
