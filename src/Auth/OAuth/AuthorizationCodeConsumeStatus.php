<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum AuthorizationCodeConsumeStatus
{
    case CONSUMED;
    case EXPIRED;
    case INVALID;
    case REPLAYED;
}
