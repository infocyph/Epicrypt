<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Throwable;

final readonly class OpenIdUserInfoProjector
{
    public function __construct(
        private OpenIdSubjectIdentifierProviderInterface $subjects,
        private OpenIdClaimsProviderInterface $claims,
    ) {}

    /**
     * @param array<array-key, mixed> $scopes
     * @return array<string, mixed>
     */
    public function project(string $principalId, string $clientId, array $scopes): array
    {
        AuthProtocolPolicy::assertText($principalId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OpenID principal ID');
        AuthProtocolPolicy::assertText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OpenID client ID');
        $normalizedScopes = AuthProtocolPolicy::normalizeScopes($scopes, 'OpenID UserInfo scopes');
        if (!in_array('openid', $normalizedScopes, true)) {
            throw new ConfigurationException('OpenID UserInfo projection requires the openid scope.');
        }

        $subject = $this->subjects->subject($principalId, $clientId);
        AuthProtocolPolicy::assertText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OpenID subject');
        $claims = $this->claims->claims($principalId, $clientId, $normalizedScopes);
        if (count($claims) >= AuthProtocolPolicy::MAX_AUTH_CLAIMS || array_key_exists('sub', $claims)) {
            throw new ConfigurationException('OpenID UserInfo claims exceed bounds or attempt to override sub.');
        }

        foreach ($claims as $name => $value) {
            if (!AuthProtocolPolicy::validText($name, AuthProtocolPolicy::MAX_PARAMETER_NAME_BYTES)) {
                throw new ConfigurationException('OpenID UserInfo claim name is invalid.');
            }
            try {
                json_encode($value, JSON_THROW_ON_ERROR, AuthProtocolPolicy::MAX_JSON_DEPTH);
            } catch (Throwable $exception) {
                throw new ConfigurationException('OpenID UserInfo claim value is not bounded JSON.', 0, $exception);
            }
        }

        return ['sub' => $subject] + $claims;
    }
}
