<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthTokenResponse
{
    private const array RESERVED_PARAMETERS = [
        'access_token' => true,
        'token_type' => true,
        'expires_in' => true,
        'scope' => true,
        'refresh_token' => true,
    ];

    /** @var array<string, string> */
    public array $additionalParameters;

    /**
     * @param list<string> $scopes
     * @param array<string, string> $additionalParameters
     */
    public function __construct(
        #[\SensitiveParameter]
        public string $accessToken,
        public OAuthAccessTokenType $tokenType,
        public int $expiresIn,
        public array $scopes,
        #[\SensitiveParameter]
        public ?string $refreshToken = null,
        #[\SensitiveParameter]
        array $additionalParameters = [],
    ) {
        $this->additionalParameters = self::normalizeAdditionalParameters($additionalParameters);
    }

    /** @return array<string, mixed> */
    public function parameters(): array
    {
        return [
            'access_token' => $this->accessToken,
            'token_type' => $this->tokenType->value,
            'expires_in' => $this->expiresIn,
            ...($this->scopes === [] ? [] : ['scope' => implode(' ', $this->scopes)]),
            ...($this->refreshToken === null ? [] : ['refresh_token' => $this->refreshToken]),
            ...$this->additionalParameters,
        ];
    }

    /**
     * @param array<string, string> $parameters
     * @return array<string, string>
     */
    private static function normalizeAdditionalParameters(#[\SensitiveParameter] array $parameters): array
    {
        if (count($parameters) > AuthProtocolPolicy::MAX_PARAMETERS) {
            throw new ConfigurationException('OAuth token-response extension parameter count exceeds the supported limit.');
        }

        foreach ($parameters as $name => $value) {
            if (isset(self::RESERVED_PARAMETERS[$name])
                || !AuthProtocolPolicy::validParameterName($name)
                || $value === ''
                || strlen($value) > AuthProtocolPolicy::MAX_COMPACT_TOKEN_BYTES
                || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
                throw new ConfigurationException('OAuth token-response extension parameter is invalid or reserved.');
            }
        }

        return $parameters;
    }
}
