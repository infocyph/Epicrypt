<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

final readonly class OAuthClientAuthenticator
{
    public function __construct(
        private OAuthClientStoreInterface $clients,
        private OAuthClientAssertionValidator $assertions,
    ) {}

    public function authenticatePrivateKeyJwt(
        string $clientId,
        #[\SensitiveParameter]
        string $assertion,
        string $audience,
    ): OAuthClientAuthenticationResult {
        $client = $this->enabledClient($clientId);
        if (!$client instanceof OAuthClient) {
            return OAuthClientAuthenticationResult::failure(OAuthClientAuthenticationFailureReason::INVALID_CLIENT);
        }
        if (!$client->allowsAuthenticationMethod(OAuthClientAuthenticationMethod::PRIVATE_KEY_JWT)) {
            return OAuthClientAuthenticationResult::failure(OAuthClientAuthenticationFailureReason::METHOD_NOT_ALLOWED);
        }

        $result = $this->assertions->validate($client, $assertion, $audience);
        if ($result->valid) {
            return OAuthClientAuthenticationResult::success($client);
        }

        return OAuthClientAuthenticationResult::failure(
            $result->status === OAuthClientAssertionStatus::REPLAYED
                ? OAuthClientAuthenticationFailureReason::REPLAYED_ASSERTION
                : OAuthClientAuthenticationFailureReason::INVALID_ASSERTION,
            $result->status,
        );
    }

    public function authenticateSecret(
        string $clientId,
        OAuthClientAuthenticationMethod $method,
        #[\SensitiveParameter]
        string $secret,
    ): OAuthClientAuthenticationResult {
        $client = $this->enabledClient($clientId);
        if (!$client instanceof OAuthClient) {
            return OAuthClientAuthenticationResult::failure(OAuthClientAuthenticationFailureReason::INVALID_CLIENT);
        }
        if (!$method->usesClientSecret() || !$client->allowsAuthenticationMethod($method)) {
            return OAuthClientAuthenticationResult::failure(OAuthClientAuthenticationFailureReason::METHOD_NOT_ALLOWED);
        }
        if (!$client->verifySecret($secret)) {
            return OAuthClientAuthenticationResult::failure(OAuthClientAuthenticationFailureReason::INVALID_SECRET);
        }

        return OAuthClientAuthenticationResult::success($client);
    }

    private function enabledClient(string $clientId): ?OAuthClient
    {
        $client = $this->clients->find($clientId);

        return $client?->enabled === true ? $client : null;
    }
}
