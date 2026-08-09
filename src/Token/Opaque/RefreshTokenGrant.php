<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Opaque;

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
        public string $id,
        public string $subject,
        public string $clientId,
        array $audiences,
        array $scopes,
        public int $expiresAt,
        public ?string $dpopKeyThumbprint = null,
    ) {
        self::assertIdentifier($this->id, 128, 'Refresh-token grant ID');
        self::assertIdentifier($this->subject, 255, 'Refresh-token subject');
        self::assertIdentifier($this->clientId, 255, 'Refresh-token client ID');
        $this->audiences = self::normalizeAudiences($audiences);
        $this->scopes = self::normalizeScopes($scopes);
        if ($this->expiresAt < 1) {
            throw new ConfigurationException('Refresh-token grant expiration must be a positive timestamp.');
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
        if (!array_is_list($scopes)) {
            throw new ConfigurationException('Refresh-token scopes must be a list.');
        }
        $unique = [];
        $normalized = [];
        foreach ($scopes as $scope) {
            if (!is_string($scope) || preg_match('/\A[\x21\x23-\x5B\x5D-\x7E]+\z/D', $scope) !== 1 || isset($unique[$scope])) {
                throw new ConfigurationException('Refresh-token scopes must contain unique OAuth scope tokens.');
            }
            $unique[$scope] = true;
            $normalized[] = $scope;
        }

        return $normalized;
    }

    public static function validDpopKeyThumbprint(string $thumbprint): bool
    {
        return preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $thumbprint) === 1;
    }

    private static function assertIdentifier(string $value, int $maximumLength, string $label): void
    {
        if ($value === '' || strlen($value) > $maximumLength || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new ConfigurationException(sprintf('%s is invalid.', $label));
        }
    }

    /**
     * @param array<array-key, mixed> $audiences
     * @return list<string>
     */
    private static function normalizeAudiences(array $audiences): array
    {
        if ($audiences === [] || !array_is_list($audiences)) {
            throw new ConfigurationException('Refresh-token audiences must be a non-empty list.');
        }
        $unique = [];
        $normalized = [];
        foreach ($audiences as $audience) {
            if (!is_string($audience) || $audience === '' || strlen($audience) > 2048 || isset($unique[$audience])) {
                throw new ConfigurationException('Refresh-token audiences must contain unique non-empty strings.');
            }
            $unique[$audience] = true;
            $normalized[] = $audience;
        }

        return $normalized;
    }
}
