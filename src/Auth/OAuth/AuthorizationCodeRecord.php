<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Json;

final readonly class AuthorizationCodeRecord
{
    public function __construct(
        public string $codeId,
        public string $authorizationId,
        public int $expiresAt,
        public string $stateDigest,
    ) {
        if (preg_match('/\A[A-Za-z0-9_-]{32}\z/D', $this->codeId) !== 1) {
            throw new ConfigurationException('Authorization-code record ID must be a 192-bit Base64URL value.');
        }
        AuthProtocolPolicy::assertText(
            $this->authorizationId,
            AuthProtocolPolicy::MAX_IDENTIFIER_BYTES,
            'Authorization-code record authorization ID',
        );
        if ($this->expiresAt < 1) {
            throw new ConfigurationException('Authorization-code record expiration must be a positive timestamp.');
        }
        if (preg_match('/\A[a-f0-9]{64}\z/D', $this->stateDigest) !== 1) {
            throw new ConfigurationException('Authorization-code record state digest must be lowercase SHA-256 hex.');
        }
    }

    public static function fromCode(AuthorizationCode $code): self
    {
        return new self(
            codeId: $code->codeId,
            authorizationId: $code->authorizationId,
            expiresAt: $code->expiresAt,
            stateDigest: hash('sha256', Json::encode($code->toArray())),
        );
    }

    public function sameState(self $other): bool
    {
        return $this->codeId === $other->codeId
            && $this->authorizationId === $other->authorizationId
            && $this->expiresAt === $other->expiresAt
            && hash_equals($this->stateDigest, $other->stateDigest);
    }
}
