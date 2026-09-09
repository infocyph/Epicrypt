<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthAuthorizationRequest
{
    /** @var list<string> */
    public array $scopes;

    /** @var non-empty-list<string> */
    public array $audiences;

    /**
     * @param array<array-key, mixed> $scopes
     * @param array<array-key, mixed> $audiences
     */
    public function __construct(
        public string $clientId,
        public string $redirectUri,
        array $scopes,
        array $audiences,
        public string $codeChallenge,
        public ?string $state = null,
    ) {
        AuthProtocolPolicy::assertText($this->clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OAuth authorization client ID');
        AuthProtocolPolicy::assertText($this->redirectUri, AuthProtocolPolicy::MAX_REDIRECT_URI_BYTES, 'OAuth authorization redirect URI');
        $this->scopes = AuthProtocolPolicy::normalizeScopes($scopes, 'OAuth authorization request scopes');
        $this->audiences = AuthProtocolPolicy::normalizeAudiences($audiences, 'OAuth authorization request audiences');
        if (!AuthProtocolPolicy::validSha256Base64Url($this->codeChallenge)) {
            throw new ConfigurationException('OAuth authorization PKCE challenge must be a SHA-256 Base64URL value.');
        }
        if ($this->state !== null
            && ($this->state === '' || !AuthProtocolPolicy::validParameterValue($this->state))) {
            throw new ConfigurationException('OAuth authorization state is invalid.');
        }
    }
}
