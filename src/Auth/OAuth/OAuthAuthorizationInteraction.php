<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthAuthorizationInteraction
{
    /** @var list<string> */
    public array $authenticationMethods;

    private function __construct(
        public OAuthAuthorizationRequest $request,
        public OAuthClient $client,
        public OAuthAuthorizationInteractionRequirement $requirement,
        public ?string $subject = null,
        public ?int $authenticationTime = null,
        public ?string $authenticationContext = null,
        array $authenticationMethods = [],
    ) {
        if (!hash_equals($this->client->clientId, $this->request->clientId)
            || !$this->client->enabled
            || !$this->client->allowsGrant(OAuthGrantType::AUTHORIZATION_CODE)
            || !$this->client->allowsRedirectUri($this->request->redirectUri)
            || array_any($this->request->scopes, fn(string $scope): bool => !$this->client->allowsScope($scope))
            || array_any($this->request->audiences, fn(string $audience): bool => !$this->client->allowsAudience($audience))) {
            throw new ConfigurationException('OAuth authorization interaction does not match the validated client request.');
        }

        $this->authenticationMethods = AuthProtocolPolicy::normalizeAuthenticationMethods(
            $authenticationMethods,
            'OAuth authorization interaction authentication methods',
        );

        if ($this->requirement === OAuthAuthorizationInteractionRequirement::SUBJECT_AUTHENTICATION) {
            if ($this->subject !== null
                || $this->authenticationTime !== null
                || $this->authenticationContext !== null
                || $this->authenticationMethods !== []) {
                throw new ConfigurationException('Subject-authentication interaction must not contain authenticated-subject state.');
            }

            return;
        }

        if ($this->subject === null) {
            throw new ConfigurationException('Authorization-decision interaction requires an authenticated subject.');
        }
        AuthProtocolPolicy::assertText(
            $this->subject,
            AuthProtocolPolicy::MAX_IDENTIFIER_BYTES,
            'OAuth authorization interaction subject',
        );
        if ($this->authenticationTime === null || $this->authenticationTime < 1) {
            throw new ConfigurationException('Authorization-decision interaction requires a positive authentication time.');
        }
        if ($this->authenticationContext !== null) {
            AuthProtocolPolicy::assertText(
                $this->authenticationContext,
                AuthProtocolPolicy::MAX_IDENTIFIER_BYTES,
                'OAuth authorization interaction context',
            );
        }
    }

    public static function authenticationRequired(
        OAuthAuthorizationRequest $request,
        OAuthClient $client,
    ): self {
        return new self(
            $request,
            $client,
            OAuthAuthorizationInteractionRequirement::SUBJECT_AUTHENTICATION,
        );
    }

    /** @param array<array-key, mixed> $authenticationMethods */
    public static function authorizationDecisionRequired(
        OAuthAuthorizationRequest $request,
        OAuthClient $client,
        string $subject,
        int $authenticationTime,
        ?string $authenticationContext = null,
        array $authenticationMethods = [],
    ): self {
        return new self(
            request: $request,
            client: $client,
            requirement: OAuthAuthorizationInteractionRequirement::AUTHORIZATION_DECISION,
            subject: $subject,
            authenticationTime: $authenticationTime,
            authenticationContext: $authenticationContext,
            authenticationMethods: $authenticationMethods,
        );
    }
}
