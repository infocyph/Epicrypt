<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Token;

use Infocyph\Epicrypt\Security\KeyPurpose;

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

    public function keyDomain(): ?string
    {
        return match ($this) {
            self::OAUTH_ACCESS_TOKEN => 'oauth.access-token.signing.v1',
            self::OAUTH_AUTHORIZATION_CODE => 'oauth.authorization-code.protection.v1',
            self::OAUTH_REFRESH_TOKEN => 'oauth.refresh-token.protection.v1',
            self::OIDC_ID_TOKEN => 'oidc.id-token.signing.v1',
            self::PERSONAL_ACCESS_TOKEN => 'api.personal-token.signing.v1',
            self::DPOP_PROOF, self::OAUTH_CLIENT_ASSERTION => null,
        };
    }

    public function keyPurpose(): ?KeyPurpose
    {
        return match ($this) {
            self::OAUTH_ACCESS_TOKEN => KeyPurpose::OAUTH_ACCESS_TOKEN_SIGNING,
            self::OAUTH_AUTHORIZATION_CODE => KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION,
            self::OAUTH_REFRESH_TOKEN => KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION,
            self::OIDC_ID_TOKEN => KeyPurpose::OIDC_ID_TOKEN_SIGNING,
            self::PERSONAL_ACCESS_TOKEN => KeyPurpose::API_PERSONAL_TOKEN_SIGNING,
            self::DPOP_PROOF, self::OAUTH_CLIENT_ASSERTION => null,
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
