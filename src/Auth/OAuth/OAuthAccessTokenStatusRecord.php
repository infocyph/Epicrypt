<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthAccessTokenStatusRecord
{
    private const int MAX_TOKEN_ID_BYTES = 128;

    public function __construct(
        public string $issuer,
        public string $tokenId,
        public string $subject,
        public string $clientId,
        public int $expiresAt,
        public ?string $authorizationId = null,
        public ?int $revokedAt = null,
    ) {
        AuthProtocolPolicy::assertText($this->issuer, AuthProtocolPolicy::MAX_ISSUER_BYTES, 'OAuth access-token issuer');
        AuthProtocolPolicy::assertText($this->tokenId, self::MAX_TOKEN_ID_BYTES, 'OAuth access-token ID');
        AuthProtocolPolicy::assertText($this->subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth access-token subject');
        AuthProtocolPolicy::assertText($this->clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth access-token client ID');
        if ($this->authorizationId !== null) {
            AuthProtocolPolicy::assertText(
                $this->authorizationId,
                AuthProtocolPolicy::MAX_IDENTIFIER_BYTES,
                'OAuth access-token authorization ID',
            );
        }
        if ($this->expiresAt < 1) {
            throw new ConfigurationException('OAuth access-token expiration must be positive.');
        }
        if ($this->revokedAt !== null && $this->revokedAt < 1) {
            throw new ConfigurationException('OAuth access-token revocation timestamp must be positive.');
        }
    }

    public function isActive(int $now): bool
    {
        return $now < $this->expiresAt
            && $this->revokedAt === null;
    }

    public function revoked(int $revokedAt): self
    {
        if ($this->revokedAt !== null) {
            return $this;
        }

        return new self(
            $this->issuer,
            $this->tokenId,
            $this->subject,
            $this->clientId,
            $this->expiresAt,
            $this->authorizationId,
            $revokedAt,
        );
    }
}
