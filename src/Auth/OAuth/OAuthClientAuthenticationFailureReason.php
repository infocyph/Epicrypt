<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthClientAuthenticationFailureReason: string
{
    case INVALID_CLIENT = 'invalid_client';
    case METHOD_NOT_ALLOWED = 'method_not_allowed';
    case INVALID_SECRET = 'invalid_secret';
    case INVALID_ASSERTION = 'invalid_assertion';
    case REPLAYED_ASSERTION = 'replayed_assertion';
}
