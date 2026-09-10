<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthEndpointCapabilityCatalog
{
    /** @var list<OAuthClientAuthenticationMethod> */
    public array $clientAuthenticationMethods;

    /** @var list<OAuthEndpointCapability> */
    public array $endpoints;

    /** @var list<OAuthGrantType> */
    public array $grantTypes;

    /**
     * @param array<array-key, mixed> $endpoints
     * @param array<array-key, mixed> $grantTypes
     * @param array<array-key, mixed> $clientAuthenticationMethods
     */
    public function __construct(array $endpoints, array $grantTypes, array $clientAuthenticationMethods)
    {
        $this->endpoints = self::normalizeTypedList($endpoints, OAuthEndpointCapability::class, 'OAuth endpoint capabilities');
        $this->grantTypes = self::normalizeTypedList($grantTypes, OAuthGrantType::class, 'OAuth grant capabilities');
        $this->clientAuthenticationMethods = self::normalizeTypedList(
            $clientAuthenticationMethods,
            OAuthClientAuthenticationMethod::class,
            'OAuth client-authentication capabilities',
        );
    }

    /** @return list<string> */
    public function codeChallengeMethods(): array
    {
        return $this->supportsEndpoint(OAuthEndpointCapability::AUTHORIZATION) ? ['S256'] : [];
    }

    /** @return list<string> */
    public function responseTypes(): array
    {
        return $this->supportsEndpoint(OAuthEndpointCapability::AUTHORIZATION) ? ['code'] : [];
    }

    public function supportsClientAuthentication(OAuthClientAuthenticationMethod $method): bool
    {
        return in_array($method, $this->clientAuthenticationMethods, true);
    }

    public function supportsEndpoint(OAuthEndpointCapability $capability): bool
    {
        return in_array($capability, $this->endpoints, true);
    }

    public function supportsGrant(OAuthGrantType $grantType): bool
    {
        return in_array($grantType, $this->grantTypes, true);
    }

    /**
     * @template T of \BackedEnum
     * @param array<array-key, mixed> $values
     * @param class-string<T> $type
     * @return list<T>
     */
    private static function normalizeTypedList(array $values, string $type, string $label): array
    {
        if (!array_is_list($values)) {
            throw new ConfigurationException($label . ' must be a list.');
        }

        $seen = [];
        $normalized = [];
        foreach ($values as $value) {
            if (!$value instanceof $type || isset($seen[$value->value])) {
                throw new ConfigurationException($label . ' must contain unique typed values.');
            }
            $seen[$value->value] = true;
            $normalized[] = $value;
        }

        return $normalized;
    }
}
