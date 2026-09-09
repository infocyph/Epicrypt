<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum RefreshTokenInspectionStatus: string
{
    case ACTIVE = 'active';

    case CONSUMED = 'consumed';

    case EXPIRED = 'expired';

    case INVALID = 'invalid';

    case REVOKED = 'revoked';
}
