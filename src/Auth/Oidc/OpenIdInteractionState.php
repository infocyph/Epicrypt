<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OpenIdInteractionState
{
    /** @var list<string> */
    public array $authenticationMethods;

    /** @param array<array-key, mixed> $authenticationMethods */
    public function __construct(
        public ?string $subject = null,
        public ?int $authenticationTime = null,
        public ?string $authenticationContext = null,
        array $authenticationMethods = [],
        public bool $consentRequired = true,
        public bool $accountSelectionRequired = false,
    ) {
        $this->authenticationMethods = AuthProtocolPolicy::normalizeAuthenticationMethods(
            $authenticationMethods,
            'OpenID Connect current authentication methods',
        );
        if ($this->subject === null) {
            if ($this->authenticationTime !== null
                || $this->authenticationContext !== null
                || $this->authenticationMethods !== []) {
                throw new ConfigurationException('Unauthenticated OpenID interaction state cannot contain authentication details.');
            }
            return;
        }

        AuthProtocolPolicy::assertText($this->subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'OpenID subject');
        if ($this->authenticationTime === null || $this->authenticationTime < 1) {
            throw new ConfigurationException('Authenticated OpenID interaction state requires a positive authentication time.');
        }
        if ($this->authenticationContext !== null) {
            AuthProtocolPolicy::assertText(
                $this->authenticationContext,
                AuthProtocolPolicy::MAX_IDENTIFIER_BYTES,
                'OpenID authentication context',
            );
        }
    }

    public function authenticated(): bool
    {
        return $this->subject !== null;
    }
}
