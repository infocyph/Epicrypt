<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthClientAssertionStatus: string
{
    case VALID = 'valid';
    case MALFORMED = 'malformed';
    case INVALID_HEADER = 'invalid_header';
    case INVALID_CLAIMS = 'invalid_claims';
    case INVALID_SIGNATURE = 'invalid_signature';
    case EXPIRED = 'expired';
    case NOT_YET_VALID = 'not_yet_valid';
    case REPLAYED = 'replayed';
}
