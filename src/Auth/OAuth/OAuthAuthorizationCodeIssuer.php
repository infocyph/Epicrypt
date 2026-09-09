<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class OAuthAuthorizationCodeIssuer
{
    private const int STORAGE_ATTEMPTS = 3;

    public function __construct(
        private OAuthAuthorizationStoreInterface $authorizations,
        private AuthorizationCodeStoreInterface $codes,
        private AuthorizationCodeArtifact $artifact,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function issue(
        OAuthAuthorizationRequest $request,
        OAuthAuthorizationApproval $approval,
        int $codeLifetimeSeconds = AuthorizationCode::DEFAULT_LIFETIME_SECONDS,
        ?string $nonce = null,
    ): OAuthAuthorizationCodeIssueResult {
        $this->assertApproval($request, $approval, $codeLifetimeSeconds, $nonce);
        $now = $this->clock->now()->getTimestamp();

        $authorization = $this->createAuthorization($request, $approval, $now);

        try {
            for ($attempt = 0; $attempt < self::STORAGE_ATTEMPTS; $attempt++) {
                $issue = $this->artifact->issue(
                    authorizationId: $authorization->authorizationId,
                    subject: $authorization->subject,
                    clientId: $authorization->clientId,
                    redirectUri: $request->redirectUri,
                    pkceChallenge: $request->codeChallenge,
                    scopes: $authorization->scopes,
                    audiences: $authorization->audiences,
                    lifetimeSeconds: $codeLifetimeSeconds,
                    nonce: $nonce,
                    authenticationTime: $approval->authenticationTime,
                    authenticationContext: $approval->authenticationContext,
                    authenticationMethods: $approval->authenticationMethods,
                );
                if ($this->codes->create(AuthorizationCodeRecord::fromCode($issue->code))) {
                    return new OAuthAuthorizationCodeIssueResult(
                        token: $issue->token,
                        code: $issue->code,
                        authorization: $authorization,
                        state: $request->state,
                    );
                }
            }
        } catch (Throwable $exception) {
            $this->authorizations->revoke($authorization->authorizationId, $now);

            throw $exception;
        }

        $this->authorizations->revoke($authorization->authorizationId, $now);

        throw new ConfigurationException('Unable to persist a unique OAuth authorization code.');
    }

    private function assertApproval(
        OAuthAuthorizationRequest $request,
        OAuthAuthorizationApproval $approval,
        int $codeLifetimeSeconds,
        ?string $nonce,
    ): void {
        foreach ($approval->scopes as $scope) {
            if (!in_array($scope, $request->scopes, true)) {
                throw new ConfigurationException('OAuth authorization approval scopes may only narrow the validated request.');
            }
        }
        if ($nonce !== null && !in_array('openid', $approval->scopes, true)) {
            throw new ConfigurationException('OIDC nonce can only be attached to an approved openid authorization.');
        }

        $now = $this->clock->now()->getTimestamp();
        if ($approval->authenticationTime > $now) {
            throw new ConfigurationException('OAuth authorization authentication time cannot be in the future.');
        }
        if ($codeLifetimeSeconds < 1
            || $codeLifetimeSeconds > AuthorizationCode::MAXIMUM_LIFETIME_SECONDS
            || $codeLifetimeSeconds > $approval->authorizationLifetimeSeconds) {
            throw new ConfigurationException('OAuth authorization-code lifetime exceeds the approved authorization lifetime or hard limit.');
        }
    }

    private function createAuthorization(
        OAuthAuthorizationRequest $request,
        OAuthAuthorizationApproval $approval,
        int $now,
    ): OAuthAuthorizationRecord {
        for ($attempt = 0; $attempt < self::STORAGE_ATTEMPTS; $attempt++) {
            $record = new OAuthAuthorizationRecord(
                authorizationId: Base64Url::encode(random_bytes(24)),
                subject: $approval->subject,
                clientId: $request->clientId,
                scopes: $approval->scopes,
                audiences: $request->audiences,
                authorizedAt: $now,
                expiresAt: $now + $approval->authorizationLifetimeSeconds,
            );
            if ($this->authorizations->create($record)) {
                return $record;
            }
        }

        throw new ConfigurationException('Unable to persist a unique OAuth authorization.');
    }
}
