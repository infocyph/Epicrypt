<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthAuthorizationCodeConsumeStatus: string
{
    case CONSUMED = 'consumed';
    case INVALID = 'invalid';
    case EXPIRED = 'expired';
    case REPLAYED = 'replayed';
    case CLIENT_MISMATCH = 'client_mismatch';
    case REDIRECT_MISMATCH = 'redirect_mismatch';
    case PKCE_MISMATCH = 'pkce_mismatch';
    case AUTHORIZATION_INACTIVE = 'authorization_inactive';
}
