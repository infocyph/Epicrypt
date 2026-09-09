<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum RefreshTokenRotationStatus
{
    case CLIENT_MISMATCH;
    case CONFLICT;
    case EXPIRED;
    case INVALID;
    case REUSED;
    case REVOKED;
    case ROTATED;
    case SCOPE_MISMATCH;
    case SENDER_MISMATCH;
}
