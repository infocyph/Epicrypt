<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Token\Jwt\JwtFailureReason;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;
use Throwable;

/**
 * Server-side lifecycle inspection for Epicrypt RFC 9068 access JWTs.
 *
 * The audience used to select the validation policy is read from the untrusted
 * payload only as a candidate. OAuthAccessTokenService then verifies the exact
 * same signed token and requires that audience before any state is trusted.
 */
final readonly class OAuthAccessTokenInspector
{
    public function __construct(private OAuthAccessTokenService $tokens) {}

    public function inspect(#[\SensitiveParameter] string $token): OAuthAccessTokenValidationResult
    {
        $audience = $this->candidateAudience($token);
        if ($audience === null) {
            return OAuthAccessTokenValidationResult::invalid(JwtFailureReason::MALFORMED);
        }

        try {
            return $this->tokens->validate($token, $audience);
        } catch (Throwable) {
            return OAuthAccessTokenValidationResult::invalid(JwtFailureReason::MALFORMED);
        }
    }

    public function revoke(#[\SensitiveParameter] string $token, string $clientId): bool
    {
        $audience = $this->candidateAudience($token);
        if ($audience === null) {
            return false;
        }

        try {
            return $this->tokens->revoke($token, $audience, $clientId);
        } catch (Throwable) {
            return false;
        }
    }

    /** @return non-empty-string|null */
    private function candidateAudience(#[\SensitiveParameter] string $token): ?string
    {
        try {
            [, , , , $claims] = JwtToken::parse($token);
        } catch (Throwable) {
            return null;
        }

        $audience = $claims['aud'] ?? null;
        if (is_string($audience) && $audience !== '') {
            return $audience;
        }
        if (!is_array($audience) || $audience === [] || !array_is_list($audience)) {
            return null;
        }

        $first = $audience[0] ?? null;
        return is_string($first) && $first !== '' ? $first : null;
    }
}
