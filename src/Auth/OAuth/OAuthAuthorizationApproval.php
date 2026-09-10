<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthAuthorizationApproval
{
    public const int DEFAULT_AUTHORIZATION_LIFETIME_SECONDS = 2_592_000;

    public const int MAXIMUM_AUTHORIZATION_LIFETIME_SECONDS = 31_536_000;

    /** @var list<string> */
    public array $authenticationMethods;

    /** @var list<string> */
    public array $scopes;

    /**
     * @param array<array-key, mixed> $scopes
     * @param array<array-key, mixed> $authenticationMethods
     */
    public function __construct(
        public string $subject,
        array $scopes,
        public int $authenticationTime,
        public int $authorizationLifetimeSeconds = self::DEFAULT_AUTHORIZATION_LIFETIME_SECONDS,
        public ?string $authenticationContext = null,
        array $authenticationMethods = [],
    ) {
        AuthProtocolPolicy::assertText(
            $this->subject,
            AuthProtocolPolicy::MAX_IDENTIFIER_BYTES,
            'OAuth authorization approval subject',
        );
        $this->scopes = AuthProtocolPolicy::normalizeScopes($scopes, 'OAuth authorization approval scopes');
        if ($this->authenticationTime < 1) {
            throw new ConfigurationException('OAuth authorization approval authentication time must be positive.');
        }
        if ($this->authorizationLifetimeSeconds < 1
            || $this->authorizationLifetimeSeconds > self::MAXIMUM_AUTHORIZATION_LIFETIME_SECONDS) {
            throw new ConfigurationException('OAuth authorization lifetime must be between 1 second and 1 year.');
        }
        if ($this->authenticationContext !== null) {
            AuthProtocolPolicy::assertText(
                $this->authenticationContext,
                AuthProtocolPolicy::MAX_IDENTIFIER_BYTES,
                'OAuth authorization approval authentication context',
            );
        }
        $this->authenticationMethods = AuthProtocolPolicy::normalizeAuthenticationMethods(
            $authenticationMethods,
            'OAuth authorization approval authentication methods',
        );
    }

    /** @param array<array-key, mixed> $approvedScopes */
    public static function fromInteraction(
        OAuthAuthorizationInteraction $interaction,
        array $approvedScopes,
        int $authorizationLifetimeSeconds = self::DEFAULT_AUTHORIZATION_LIFETIME_SECONDS,
    ): self {
        if ($interaction->requirement !== OAuthAuthorizationInteractionRequirement::AUTHORIZATION_DECISION
            || $interaction->subject === null
            || $interaction->authenticationTime === null) {
            throw new ConfigurationException('OAuth authorization approval requires an authorization-decision interaction.');
        }

        return new self(
            subject: $interaction->subject,
            scopes: $approvedScopes,
            authenticationTime: $interaction->authenticationTime,
            authorizationLifetimeSeconds: $authorizationLifetimeSeconds,
            authenticationContext: $interaction->authenticationContext,
            authenticationMethods: $interaction->authenticationMethods,
        );
    }
}
