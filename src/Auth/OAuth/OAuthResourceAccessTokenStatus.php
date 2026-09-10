<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthResourceAccessTokenStatus: string
{
    case DPOP_REQUIRED = 'dpop_required';

    case INVALID_DPOP_PROOF = 'invalid_dpop_proof';

    case INVALID_TOKEN = 'invalid_token';

    case VALID = 'valid';
}
