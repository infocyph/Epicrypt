<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Token;

enum AuthTokenClass: string
{
    case OAUTH_ACCESS_TOKEN = 'oauth.access-token';

    case OAUTH_AUTHORIZATION_CODE = 'oauth.authorization-code';

    case OAUTH_REFRESH_TOKEN = 'oauth.refresh-token';

    case OIDC_ID_TOKEN = 'oidc.id-token';

    case DPOP_PROOF = 'oauth.dpop-proof';

    case OAUTH_CLIENT_ASSERTION = 'oauth.client-assertion';

    case PERSONAL_ACCESS_TOKEN = 'api.personal-token';

    public function acceptsJoseType(string $type): bool
    {
        $normalized = strtolower($type);

        return hash_equals(strtolower($this->joseType()), $normalized)
            || hash_equals($this->mediaType(), $normalized);
    }

    public function joseType(): string
    {
        return match ($this) {
            self::OAUTH_ACCESS_TOKEN => 'at+jwt',
            self::OAUTH_AUTHORIZATION_CODE => 'oauth-authz-code+jwt',
            self::OAUTH_REFRESH_TOKEN => 'oauth-refresh+jwt',
            self::OIDC_ID_TOKEN, self::OAUTH_CLIENT_ASSERTION => 'JWT',
            self::DPOP_PROOF => 'dpop+jwt',
            self::PERSONAL_ACCESS_TOKEN => 'pat+jwt',
        };
    }

    public function mediaType(): string
    {
        return match ($this) {
            self::OIDC_ID_TOKEN, self::OAUTH_CLIENT_ASSERTION => 'application/jwt',
            default => 'application/' . $this->joseType(),
        };
    }

    public function requiresConfidentiality(): bool
    {
        return $this === self::OAUTH_AUTHORIZATION_CODE
            || $this === self::OAUTH_REFRESH_TOKEN;
    }
}
