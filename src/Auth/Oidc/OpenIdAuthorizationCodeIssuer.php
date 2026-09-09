<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationApproval;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationCodeIssuer;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationCodeIssueResult;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;

final readonly class OpenIdAuthorizationCodeIssuer
{
    public function __construct(
        private OAuthAuthorizationCodeIssuer $oauth,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function issue(
        OpenIdAuthorizationRequest $request,
        OAuthAuthorizationApproval $approval,
        int $codeLifetimeSeconds = \Infocyph\Epicrypt\Auth\OAuth\AuthorizationCode::DEFAULT_LIFETIME_SECONDS,
    ): OAuthAuthorizationCodeIssueResult {
        $now = $this->clock->now()->getTimestamp();
        if ($request->maximumAuthenticationAge !== null
            && ($approval->authenticationTime > $now
                || ($now - $approval->authenticationTime) > $request->maximumAuthenticationAge)) {
            throw new ConfigurationException('OpenID approval authentication time violates max_age.');
        }
        if ($request->acrValues !== []
            && ($approval->authenticationContext === null
                || !in_array($approval->authenticationContext, $request->acrValues, true))) {
            throw new ConfigurationException('OpenID approval authentication context does not satisfy acr_values.');
        }

        return $this->oauth->issue(
            $request->oauth,
            $approval,
            $codeLifetimeSeconds,
            $request->nonce,
        );
    }
}
