<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthAccessTokenType: string
{
    case BEARER = 'Bearer';

    case DPOP = 'DPoP';
}
