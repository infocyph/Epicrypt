<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthAccessTokenValidationStatus: string
{
    case VALID = 'valid';
    case INVALID_TOKEN = 'invalid_token';
    case STATUS_INACTIVE = 'status_inactive';
    case AUTHORIZATION_INACTIVE = 'authorization_inactive';
    case STATE_MISMATCH = 'state_mismatch';
}
