<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;

final readonly class OpenIdInteractionPolicy
{
    public function __construct(private ClockInterface $clock = new SystemClock()) {}

    public function evaluate(
        OpenIdAuthorizationRequest $request,
        OpenIdInteractionState $state,
    ): OpenIdInteractionResult {
        if ($this->requiresAuthentication($request, $state)) {
            return $request->hasPrompt(OpenIdPrompt::NONE)
                ? OpenIdInteractionResult::error(OpenIdInteractionErrorCode::LOGIN_REQUIRED)
                : OpenIdInteractionResult::require(OpenIdInteractionRequirement::SUBJECT_AUTHENTICATION);
        }

        if ($request->hasPrompt(OpenIdPrompt::SELECT_ACCOUNT) || $state->accountSelectionRequired) {
            return $request->hasPrompt(OpenIdPrompt::NONE)
                ? OpenIdInteractionResult::error(OpenIdInteractionErrorCode::ACCOUNT_SELECTION_REQUIRED)
                : OpenIdInteractionResult::require(OpenIdInteractionRequirement::ACCOUNT_SELECTION);
        }

        if ($request->hasPrompt(OpenIdPrompt::CONSENT) || $state->consentRequired) {
            return $request->hasPrompt(OpenIdPrompt::NONE)
                ? OpenIdInteractionResult::error(OpenIdInteractionErrorCode::CONSENT_REQUIRED)
                : OpenIdInteractionResult::require(OpenIdInteractionRequirement::AUTHORIZATION_DECISION);
        }

        return OpenIdInteractionResult::require(OpenIdInteractionRequirement::READY);
    }

    private function requiresAuthentication(
        OpenIdAuthorizationRequest $request,
        OpenIdInteractionState $state,
    ): bool {
        if (!$state->authenticated() || $request->hasPrompt(OpenIdPrompt::LOGIN)) {
            return true;
        }

        $now = $this->clock->now()->getTimestamp();
        if ($state->authenticationTime === null || $state->authenticationTime > $now) {
            return true;
        }
        if ($request->maximumAuthenticationAge !== null
            && ($now - $state->authenticationTime) > $request->maximumAuthenticationAge) {
            return true;
        }

        return $request->acrValues !== []
            && ($state->authenticationContext === null
                || !in_array($state->authenticationContext, $request->acrValues, true));
    }
}
