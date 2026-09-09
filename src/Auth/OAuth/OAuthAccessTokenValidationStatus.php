<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthAccessTokenValidationStatus: string
{
    case AUTHORIZATION_INACTIVE = 'authorization_inactive';

    case INVALID_TOKEN = 'invalid_token';

    case STATE_MISMATCH = 'state_mismatch';

    case STATUS_INACTIVE = 'status_inactive';

    case VALID = 'valid';
}
