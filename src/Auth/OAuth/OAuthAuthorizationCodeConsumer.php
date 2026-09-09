<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;

final readonly class OAuthAuthorizationCodeConsumer
{
    public function __construct(
        private AuthorizationCodeArtifact $artifact,
        private AuthorizationCodeStoreInterface $codes,
        private OAuthAuthorizationStoreInterface $authorizations,
        private ClockInterface $clock = new SystemClock(),
    ) {}

    public function consume(
        #[\SensitiveParameter]
        string $token,
        string $clientId,
        string $redirectUri,
        #[\SensitiveParameter]
        string $pkceVerifier,
    ): OAuthAuthorizationCodeConsumeResult {
        try {
            $code = $this->artifact->decrypt($token);
        } catch (InvalidTokenException) {
            return OAuthAuthorizationCodeConsumeResult::failure(OAuthAuthorizationCodeConsumeStatus::INVALID);
        }

        if (!$code->matchesClient($clientId)) {
            return OAuthAuthorizationCodeConsumeResult::failure(OAuthAuthorizationCodeConsumeStatus::CLIENT_MISMATCH);
        }
        if (!$code->matchesRedirectUri($redirectUri)) {
            return OAuthAuthorizationCodeConsumeResult::failure(OAuthAuthorizationCodeConsumeStatus::REDIRECT_MISMATCH);
        }
        if (!$code->matchesPkceVerifier($pkceVerifier)) {
            return OAuthAuthorizationCodeConsumeResult::failure(OAuthAuthorizationCodeConsumeStatus::PKCE_MISMATCH);
        }

        $now = $this->clock->now()->getTimestamp();
        $authorization = $this->authorizations->find($code->authorizationId);
        if (!$authorization instanceof OAuthAuthorizationRecord
            || !$authorization->isActive($now)
            || !$authorization->matchesCode($code)) {
            return OAuthAuthorizationCodeConsumeResult::failure(OAuthAuthorizationCodeConsumeStatus::AUTHORIZATION_INACTIVE);
        }

        $status = $this->codes->consume(AuthorizationCodeRecord::fromCode($code), $now);
        if ($status !== AuthorizationCodeConsumeStatus::CONSUMED) {
            return OAuthAuthorizationCodeConsumeResult::failure(match ($status) {
                AuthorizationCodeConsumeStatus::REPLAYED => OAuthAuthorizationCodeConsumeStatus::REPLAYED,
                AuthorizationCodeConsumeStatus::EXPIRED => OAuthAuthorizationCodeConsumeStatus::EXPIRED,
                AuthorizationCodeConsumeStatus::INVALID => OAuthAuthorizationCodeConsumeStatus::INVALID,
                AuthorizationCodeConsumeStatus::CONSUMED => OAuthAuthorizationCodeConsumeStatus::INVALID,
            });
        }

        $authorization = $this->authorizations->find($code->authorizationId);
        if (!$authorization instanceof OAuthAuthorizationRecord
            || !$authorization->isActive($now)
            || !$authorization->matchesCode($code)) {
            return OAuthAuthorizationCodeConsumeResult::failure(OAuthAuthorizationCodeConsumeStatus::AUTHORIZATION_INACTIVE);
        }

        return OAuthAuthorizationCodeConsumeResult::success($code, $authorization);
    }
}
