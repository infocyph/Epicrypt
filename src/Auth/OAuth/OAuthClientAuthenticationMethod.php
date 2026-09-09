<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthClientAuthenticationMethod: string
{
    case CLIENT_SECRET_BASIC = 'client_secret_basic';

    case CLIENT_SECRET_POST = 'client_secret_post';

    case NONE = 'none';

    case PRIVATE_KEY_JWT = 'private_key_jwt';

    public function usesClientSecret(): bool
    {
        return $this === self::CLIENT_SECRET_BASIC || $this === self::CLIENT_SECRET_POST;
    }
}
