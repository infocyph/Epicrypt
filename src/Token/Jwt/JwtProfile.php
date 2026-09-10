<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

enum JwtProfile
{
    case EPICRYPT;

    case GENERIC;

    case OAUTH_ACCESS_TOKEN;

    case OPENID_ID_TOKEN;

    case PERSONAL_ACCESS_TOKEN;
}
