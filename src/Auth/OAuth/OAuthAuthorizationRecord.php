<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthAuthorizationRecord
{
    /** @var non-empty-list<string> */
    public array $audiences;

    /** @var list<string> */
    public array $scopes;

    /**
     * @param array<array-key, mixed> $scopes
     * @param array<array-key, mixed> $audiences
     */
    public function __construct(
        public string $authorizationId,
        public string $subject,
        public string $clientId,
        array $scopes,
        array $audiences,
        public int $authorizedAt,
        public int $expiresAt,
        public ?int $revokedAt = null,
    ) {
        AuthProtocolPolicy::assertText($this->authorizationId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth authorization ID');
        AuthProtocolPolicy::assertText($this->subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth authorization subject');
        AuthProtocolPolicy::assertText($this->clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth authorization client ID');
        $this->scopes = AuthProtocolPolicy::normalizeScopes($scopes, 'OAuth authorization scopes');
        /** @var non-empty-list<string> $normalizedAudiences */
        $normalizedAudiences = AuthProtocolPolicy::normalizeAudiences($audiences, 'OAuth authorization audiences');
        $this->audiences = $normalizedAudiences;
        if ($this->authorizedAt < 1 || $this->expiresAt <= $this->authorizedAt) {
            throw new ConfigurationException('OAuth authorization lifetime is invalid.');
        }
        if ($this->revokedAt !== null && $this->revokedAt < $this->authorizedAt) {
            throw new ConfigurationException('OAuth authorization revocation cannot predate authorization.');
        }
    }

    public function isActive(int $now): bool
    {
        return $now >= $this->authorizedAt
            && $now < $this->expiresAt
            && $this->revokedAt === null;
    }

    public function matchesCode(AuthorizationCode $code): bool
    {
        return $this->authorizationId === $code->authorizationId
            && $this->subject === $code->subject
            && $this->clientId === $code->clientId
            && $this->scopes === $code->scopes
            && $this->audiences === $code->audiences;
    }

    public function matchesRefreshGrant(RefreshTokenGrant $grant): bool
    {
        return $this->authorizationId === $grant->authorizationId
            && $this->subject === $grant->subject
            && $this->clientId === $grant->clientId
            && $this->audiences === $grant->audiences
            && self::containsScopes($this->scopes, $grant->scopes)
            && $grant->expiresAt <= $this->expiresAt;
    }

    public function revoked(int $revokedAt): self
    {
        if ($this->revokedAt !== null) {
            return $this;
        }

        return new self(
            $this->authorizationId,
            $this->subject,
            $this->clientId,
            $this->scopes,
            $this->audiences,
            $this->authorizedAt,
            $this->expiresAt,
            $revokedAt,
        );
    }

    /**
     * @param list<string> $allowed
     * @param list<string> $requested
     */
    private static function containsScopes(array $allowed, array $requested): bool
    {
        return array_all(
            $requested,
            static fn(string $scope): bool => in_array($scope, $allowed, true),
        );
    }
}
