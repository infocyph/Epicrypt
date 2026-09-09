<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthErrorCode: string
{
    case ACCESS_DENIED = 'access_denied';

    case INVALID_CLIENT = 'invalid_client';

    case INVALID_DPOP_PROOF = 'invalid_dpop_proof';

    case INVALID_GRANT = 'invalid_grant';

    case INVALID_REQUEST = 'invalid_request';

    case INVALID_SCOPE = 'invalid_scope';

    case SERVER_ERROR = 'server_error';

    case TEMPORARILY_UNAVAILABLE = 'temporarily_unavailable';

    case UNAUTHORIZED_CLIENT = 'unauthorized_client';

    case UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';

    case UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';
}
