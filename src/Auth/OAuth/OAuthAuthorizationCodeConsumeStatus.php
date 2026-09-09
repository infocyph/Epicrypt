<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthAuthorizationCodeConsumeStatus: string
{
    case AUTHORIZATION_INACTIVE = 'authorization_inactive';

    case CLIENT_MISMATCH = 'client_mismatch';

    case CONSUMED = 'consumed';

    case EXPIRED = 'expired';

    case INVALID = 'invalid';

    case PKCE_MISMATCH = 'pkce_mismatch';

    case REDIRECT_MISMATCH = 'redirect_mismatch';

    case REPLAYED = 'replayed';
}
