<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

enum JwtReplayMode
{
    case DENYLIST;

    case NONE;

    case SINGLE_USE;
}
