<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequestValidator;
use Infocyph\Epicrypt\Auth\OAuth\OAuthErrorCode;
use Infocyph\Epicrypt\Auth\OAuth\OAuthProtocolError;
use Throwable;

final readonly class OpenIdAuthorizationRequestValidator
{
    private const array OIDC_SINGLETON_PARAMETERS = ['nonce', 'prompt', 'max_age', 'acr_values'];

    public function __construct(private OAuthAuthorizationRequestValidator $oauth) {}

    /**
     * Validates the shared OAuth/OIDC authorization parameter envelope.
     *
     * Requests without the exact openid scope remain ordinary OAuth requests.
     * OIDC-only parameters are parsed only after OAuth validation establishes a
     * safe redirect target and exact client/request binding.
     *
     * @param array<string, string|list<string>> $parameters
     */
    public function validate(array $parameters): OpenIdAuthorizationResult
    {
        $base = $this->oauth->validate($parameters);
        if ($base->error !== null) {
            return OpenIdAuthorizationResult::rejected($base->error);
        }
        $request = $base->request;
        $client = $base->client;
        if ($request === null || $client === null) {
            return OpenIdAuthorizationResult::rejected(new OAuthProtocolError(OAuthErrorCode::SERVER_ERROR));
        }
        if (!in_array('openid', $request->scopes, true)) {
            return OpenIdAuthorizationResult::oauth($request, $client);
        }

        try {
            foreach (self::OIDC_SINGLETON_PARAMETERS as $name) {
                if (isset($parameters[$name]) && !is_string($parameters[$name])) {
                    return $this->invalid($request->redirectUri, $request->state);
                }
            }

            $nonce = $this->optionalText($parameters, 'nonce', AuthProtocolPolicy::MAX_NONCE_BYTES);
            $prompts = $this->prompts($parameters['prompt'] ?? null);
            $maxAge = $this->maximumAuthenticationAge($parameters['max_age'] ?? null);
            $acrValues = $this->acrValues($parameters['acr_values'] ?? null);

            return OpenIdAuthorizationResult::openId(
                new OpenIdAuthorizationRequest($request, $nonce, $prompts, $maxAge, $acrValues),
                $client,
            );
        } catch (Throwable) {
            return $this->invalid($request->redirectUri, $request->state);
        }
    }

    /**
     * @param string|list<string>|null $value
     * @return list<string>
     */
    private function acrValues(string|array|null $value): array
    {
        if ($value === null) {
            return [];
        }
        if (!is_string($value) || $value === '') {
            throw new \InvalidArgumentException('Invalid OpenID Connect acr_values.');
        }
        $values = explode(' ', $value);
        if (in_array('', $values, true)) {
            throw new \InvalidArgumentException('Invalid OpenID Connect acr_values spacing.');
        }

        return $values;
    }

    private function invalid(string $redirectUri, ?string $state): OpenIdAuthorizationResult
    {
        return OpenIdAuthorizationResult::rejected(new OAuthProtocolError(
            OAuthErrorCode::INVALID_REQUEST,
            $redirectUri,
            $state,
        ));
    }

    /** @param string|list<string>|null $value */
    private function maximumAuthenticationAge(string|array|null $value): ?int
    {
        if ($value === null) {
            return null;
        }
        if (!is_string($value) || preg_match('/\A(?:0|[1-9][0-9]{0,7})\z/D', $value) !== 1) {
            throw new \InvalidArgumentException('Invalid OpenID Connect max_age.');
        }

        return (int) $value;
    }

    /** @param array<string, string|list<string>> $parameters */
    private function optionalText(array $parameters, string $name, int $maximumBytes): ?string
    {
        if (!array_key_exists($name, $parameters)) {
            return null;
        }
        $value = $parameters[$name];
        if (!is_string($value) || !AuthProtocolPolicy::validText($value, $maximumBytes)) {
            throw new \InvalidArgumentException('Invalid OpenID Connect string parameter.');
        }

        return $value;
    }

    /**
     * @param string|list<string>|null $value
     * @return list<OpenIdPrompt>
     */
    private function prompts(string|array|null $value): array
    {
        if ($value === null) {
            return [];
        }
        if (!is_string($value) || $value === '') {
            throw new \InvalidArgumentException('Invalid OpenID Connect prompt.');
        }
        $tokens = explode(' ', $value);
        if (in_array('', $tokens, true)) {
            throw new \InvalidArgumentException('Invalid OpenID Connect prompt spacing.');
        }

        return array_map(
            OpenIdPrompt::from(...),
            $tokens,
        );
    }
}
