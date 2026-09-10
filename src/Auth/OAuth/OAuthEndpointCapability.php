<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthEndpointCapability: string
{
    case AUTHORIZATION = 'authorization';

    case INTROSPECTION = 'introspection';

    case JWKS = 'jwks';

    case METADATA = 'metadata';

    case REVOCATION = 'revocation';

    case TOKEN = 'token';
}
