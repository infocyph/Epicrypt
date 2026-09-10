<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequest;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OpenIdAuthorizationRequest
{
    private const int MAX_ACR_VALUES = 16;

    private const int MAX_AUTHENTICATION_AGE_SECONDS = 2_678_400;

    /** @var list<string> */
    public array $acrValues;

    /** @var list<OpenIdPrompt> */
    public array $prompts;

    /**
     * @param array<array-key, mixed> $prompts
     * @param array<array-key, mixed> $acrValues
     */
    public function __construct(
        public OAuthAuthorizationRequest $oauth,
        public ?string $nonce = null,
        array $prompts = [],
        public ?int $maximumAuthenticationAge = null,
        array $acrValues = [],
    ) {
        if (!in_array('openid', $this->oauth->scopes, true)) {
            throw new ConfigurationException('OpenID Connect requests require the openid scope.');
        }
        if ($this->nonce !== null
            && !AuthProtocolPolicy::validText($this->nonce, AuthProtocolPolicy::MAX_NONCE_BYTES)) {
            throw new ConfigurationException('OpenID Connect nonce is invalid.');
        }
        if ($this->maximumAuthenticationAge !== null
            && ($this->maximumAuthenticationAge < 0
                || $this->maximumAuthenticationAge > self::MAX_AUTHENTICATION_AGE_SECONDS)) {
            throw new ConfigurationException('OpenID Connect max_age is outside the supported range.');
        }

        $this->prompts = self::normalizePrompts($prompts);
        $this->acrValues = self::normalizeAcrValues($acrValues);
    }

    public function hasPrompt(OpenIdPrompt $prompt): bool
    {
        return in_array($prompt, $this->prompts, true);
    }

    /**
     * @param array<array-key, mixed> $acrValues
     * @return list<string>
     */
    private static function normalizeAcrValues(array $acrValues): array
    {
        if (!array_is_list($acrValues) || count($acrValues) > self::MAX_ACR_VALUES) {
            throw new ConfigurationException('OpenID Connect acr_values must be a bounded list.');
        }

        $seen = [];
        $normalized = [];
        foreach ($acrValues as $acr) {
            if (!is_string($acr)
                || !AuthProtocolPolicy::validText($acr, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES)
                || str_contains($acr, ' ')
                || isset($seen[$acr])) {
                throw new ConfigurationException('OpenID Connect acr_values must contain unique bounded space-free values.');
            }
            $seen[$acr] = true;
            $normalized[] = $acr;
        }

        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $prompts
     * @return list<OpenIdPrompt>
     */
    private static function normalizePrompts(array $prompts): array
    {
        if (!array_is_list($prompts) || count($prompts) > count(OpenIdPrompt::cases())) {
            throw new ConfigurationException('OpenID Connect prompt values must be a bounded list.');
        }

        $seen = [];
        $normalized = [];
        foreach ($prompts as $prompt) {
            if (!$prompt instanceof OpenIdPrompt || isset($seen[$prompt->value])) {
                throw new ConfigurationException('OpenID Connect prompt values must be unique typed values.');
            }
            $seen[$prompt->value] = true;
            $normalized[] = $prompt;
        }
        if (isset($seen[OpenIdPrompt::NONE->value]) && count($normalized) !== 1) {
            throw new ConfigurationException('OpenID Connect prompt=none cannot be combined with another prompt value.');
        }

        return $normalized;
    }
}
