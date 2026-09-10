<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthClientAssertionStatus: string
{
    case EXPIRED = 'expired';

    case INVALID_CLAIMS = 'invalid_claims';

    case INVALID_HEADER = 'invalid_header';

    case INVALID_SIGNATURE = 'invalid_signature';

    case MALFORMED = 'malformed';

    case NOT_YET_VALID = 'not_yet_valid';

    case REPLAYED = 'replayed';

    case VALID = 'valid';
}
