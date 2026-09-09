<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

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
        self::assertIdentifier($this->authorizationId, 255, 'Refresh-token authorization ID');
        self::assertIdentifier($this->subject, 255, 'Refresh-token subject');
        self::assertIdentifier($this->clientId, 255, 'Refresh-token client ID');
        $this->audiences = self::normalizeAudiences($audiences);
        $this->scopes = self::normalizeScopes($scopes);
        if ($this->expiresAt < 1) {
            throw new ConfigurationException('Refresh-token authorization expiration must be a positive timestamp.');
        }
        if ($this->dpopKeyThumbprint !== null && !self::validDpopKeyThumbprint($this->dpopKeyThumbprint)) {
            throw new ConfigurationException('Refresh-token DPoP key thumbprint must be a SHA-256 Base64URL value.');
        }
    }

    /** @param array<array-key, mixed> $scopes */
    public function withScopes(array $scopes): self
    {
        $normalized = self::normalizeScopes($scopes);
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
        foreach ($other->scopes as $scope) {
            if (!in_array($scope, $this->scopes, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<array-key, mixed> $scopes
     * @return list<string>
     */
    public static function normalizeScopes(array $scopes): array
    {
        if (!array_is_list($scopes) || count($scopes) > 64) {
            throw new ConfigurationException('Refresh-token scopes must be a bounded list.');
        }
        $seen = [];
        $normalized = [];
        $totalBytes = 0;
        foreach ($scopes as $scope) {
            if (!is_string($scope)
                || strlen($scope) > 255
                || preg_match('/\A[\x21\x23-\x5B\x5D-\x7E]+\z/D', $scope) !== 1
                || isset($seen[$scope])) {
                throw new ConfigurationException('Refresh-token scopes must contain unique OAuth scope tokens.');
            }
            $totalBytes += strlen($scope) + ($normalized === [] ? 0 : 1);
            if ($totalBytes > 4096) {
                throw new ConfigurationException('Refresh-token scope value is too large.');
            }
            $seen[$scope] = true;
            $normalized[] = $scope;
        }

        return $normalized;
    }

    public static function validDpopKeyThumbprint(string $thumbprint): bool
    {
        return preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $thumbprint) === 1;
    }

    private static function assertIdentifier(string $value, int $maximumBytes, string $label): void
    {
        if ($value === '' || strlen($value) > $maximumBytes || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new ConfigurationException(sprintf('%s is invalid.', $label));
        }
    }

    /**
     * @param array<array-key, mixed> $audiences
     * @return list<string>
     */
    private static function normalizeAudiences(array $audiences): array
    {
        if ($audiences === [] || !array_is_list($audiences) || count($audiences) > 32) {
            throw new ConfigurationException('Refresh-token audiences must be a non-empty bounded list.');
        }
        $seen = [];
        $normalized = [];
        foreach ($audiences as $audience) {
            if (!is_string($audience)
                || $audience === ''
                || strlen($audience) > 2048
                || preg_match('/[\x00-\x1F\x7F]/', $audience) === 1
                || isset($seen[$audience])) {
                throw new ConfigurationException('Refresh-token audiences must contain unique bounded strings.');
            }
            $seen[$audience] = true;
            $normalized[] = $audience;
        }

        return $normalized;
    }
}
