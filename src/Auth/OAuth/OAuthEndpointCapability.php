<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthEndpointCapability: string
{
    case AUTHORIZATION = 'authorization';
    case TOKEN = 'token';
    case REVOCATION = 'revocation';
    case INTROSPECTION = 'introspection';
    case METADATA = 'metadata';
    case JWKS = 'jwks';
}
