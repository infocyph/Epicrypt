<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;

/** Transport-neutral RFC 7009 revocation core. */
final readonly class OAuthRevocationEndpoint
{
    private OAuthAccessTokenInspector $accessInspector;

    public function __construct(
        private OAuthClientStoreInterface $clients,
        private OAuthAccessTokenService $accessTokens,
        private RefreshTokenManager $refreshTokens,
        private OAuthAuthorizationStoreInterface $authorizations,
        private ClockInterface $clock = new SystemClock(),
    ) {
        if (!$this->accessTokens->immediateRevocationEnabled()) {
            throw new ConfigurationException(
                'RFC 7009 access-token revocation requires an authoritative OAuth access-token status store.',
            );
        }
        $this->accessInspector = new OAuthAccessTokenInspector($this->accessTokens);
    }

    public function revoke(
        string $clientId,
        ?OAuthClientAuthenticationResult $authentication,
        #[\SensitiveParameter]
        string $token,
        ?OAuthTokenTypeHint $hint = null,
    ): OAuthRevocationResult {
        $client = $this->resolveClient($clientId, $authentication);
        if (!$client instanceof OAuthClient) {
            return OAuthRevocationResult::failure(OAuthErrorCode::INVALID_CLIENT);
        }
        if ($token === '' || strlen($token) > AuthProtocolPolicy::MAX_COMPACT_TOKEN_BYTES) {
            return OAuthRevocationResult::failure(OAuthErrorCode::INVALID_REQUEST);
        }

        foreach ($this->inspectionOrder($hint) as $type) {
            if ($type === OAuthTokenTypeHint::REFRESH_TOKEN && $this->revokeRefresh($client, $token)) {
                return OAuthRevocationResult::success();
            }
            if ($type === OAuthTokenTypeHint::ACCESS_TOKEN && $this->revokeAccess($client, $token)) {
                return OAuthRevocationResult::success();
            }
        }

        // RFC 7009 deliberately does not reveal whether the token was unknown,
        // malformed, already inactive, or belonged to another client.
        return OAuthRevocationResult::success();
    }

    private function revokeAccess(OAuthClient $client, #[\SensitiveParameter] string $token): bool
    {
        $inspection = $this->accessInspector->inspect($token);
        if (!$inspection->cryptographicallyValid()) {
            return false;
        }
        $tokenClient = $inspection->claims['client_id'] ?? null;
        if (!is_string($tokenClient) || !hash_equals($client->clientId, $tokenClient)) {
            return false;
        }

        return $this->accessInspector->revoke($token, $client->clientId);
    }

    private function revokeRefresh(OAuthClient $client, #[\SensitiveParameter] string $token): bool
    {
        $inspection = $this->refreshTokens->inspect($token);
        $record = $inspection->record;
        if (!$record instanceof RefreshTokenRecord
            || !hash_equals($client->clientId, $record->grant->clientId)) {
            return false;
        }

        // Revoke the whole authorization, not only this refresh family. This
        // immediately invalidates every authorization-derived access JWT and all
        // refresh families while remaining idempotent for already-inactive input.
        $now = $this->clock->now()->getTimestamp();
        $this->authorizations->revoke($record->grant->authorizationId, $now);
        $this->refreshTokens->revokeAuthorization($record->grant->authorizationId);

        return true;
    }

    /** @return array{OAuthTokenTypeHint, OAuthTokenTypeHint} */
    private function inspectionOrder(?OAuthTokenTypeHint $hint): array
    {
        return match ($hint) {
            OAuthTokenTypeHint::ACCESS_TOKEN => [OAuthTokenTypeHint::ACCESS_TOKEN, OAuthTokenTypeHint::REFRESH_TOKEN],
            OAuthTokenTypeHint::REFRESH_TOKEN => [OAuthTokenTypeHint::REFRESH_TOKEN, OAuthTokenTypeHint::ACCESS_TOKEN],
            null => [OAuthTokenTypeHint::ACCESS_TOKEN, OAuthTokenTypeHint::REFRESH_TOKEN],
        };
    }

    private function resolveClient(
        string $clientId,
        ?OAuthClientAuthenticationResult $authentication,
    ): ?OAuthClient {
        if (!AuthProtocolPolicy::validText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES)) {
            return null;
        }
        $client = $this->clients->find($clientId);
        if (!$client instanceof OAuthClient || !$client->enabled) {
            return null;
        }

        if ($client->type === OAuthClientType::CONFIDENTIAL) {
            return $authentication !== null
                && $authentication->authenticated
                && $authentication->client instanceof OAuthClient
                && hash_equals($clientId, $authentication->client->clientId)
                ? $client
                : null;
        }
        if ($authentication === null) {
            return $client;
        }

        return $authentication->authenticated
            && $authentication->client instanceof OAuthClient
            && hash_equals($clientId, $authentication->client->clientId)
            ? $client
            : null;
    }
}
