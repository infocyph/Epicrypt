<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class RefreshTokenGrant
{
    /** @var list<string> */
    public array $audiences;

    /** @var list<string> */
    public array $scopes;

    /**
     * @param array<array-key, mixed> $audiences
     * @param array<array-key, mixed> $scopes
     */
    public function __construct(
        public string $authorizationId,
        public string $subject,
        public string $clientId,
        array $audiences,
        array $scopes,
        public int $expiresAt,
        public ?string $dpopKeyThumbprint = null,
    ) {
        AuthProtocolPolicy::assertText($this->authorizationId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Refresh-token authorization ID');
        AuthProtocolPolicy::assertText($this->subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Refresh-token subject');
        AuthProtocolPolicy::assertText($this->clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Refresh-token client ID');
        $this->audiences = AuthProtocolPolicy::normalizeAudiences($audiences, 'Refresh-token audiences');
        $this->scopes = AuthProtocolPolicy::normalizeScopes($scopes, 'Refresh-token scopes');
        if ($this->expiresAt < 1) {
            throw new ConfigurationException('Refresh-token authorization expiration must be a positive timestamp.');
        }
        if ($this->dpopKeyThumbprint !== null && !self::validDpopKeyThumbprint($this->dpopKeyThumbprint)) {
            throw new ConfigurationException('Refresh-token DPoP key thumbprint must be a SHA-256 Base64URL value.');
        }
    }

    /**
     * @param array<array-key, mixed> $scopes
     * @return list<string>
     */
    public static function normalizeScopes(array $scopes): array
    {
        return AuthProtocolPolicy::normalizeScopes($scopes, 'Refresh-token scopes');
    }

    public static function validDpopKeyThumbprint(string $thumbprint): bool
    {
        return AuthProtocolPolicy::validSha256Base64Url($thumbprint);
    }

    public function sameAuthorization(self $other): bool
    {
        return $this->authorizationId === $other->authorizationId
            && $this->subject === $other->subject
            && $this->clientId === $other->clientId
            && $this->audiences === $other->audiences
            && $this->expiresAt === $other->expiresAt
            && $this->dpopKeyThumbprint === $other->dpopKeyThumbprint;
    }

    public function scopesContain(self $other): bool
    {
        return array_all($other->scopes, fn($scope) => in_array($scope, $this->scopes, true));
    }

    /** @param array<array-key, mixed> $scopes */
    public function withScopes(array $scopes): self
    {
        $normalized = AuthProtocolPolicy::normalizeScopes($scopes, 'Refresh-token scopes');
        foreach ($normalized as $scope) {
            if (!in_array($scope, $this->scopes, true)) {
                throw new ConfigurationException('Refresh-token scopes may only narrow the current authorization.');
            }
        }

        return new self(
            $this->authorizationId,
            $this->subject,
            $this->clientId,
            $this->audiences,
            $normalized,
            $this->expiresAt,
            $this->dpopKeyThumbprint,
        );
    }
}
