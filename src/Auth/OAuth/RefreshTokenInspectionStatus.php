<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum RefreshTokenInspectionStatus: string
{
    case ACTIVE = 'active';
    case CONSUMED = 'consumed';
    case REVOKED = 'revoked';
    case EXPIRED = 'expired';
    case INVALID = 'invalid';
}
