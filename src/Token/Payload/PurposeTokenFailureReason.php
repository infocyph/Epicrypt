<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Payload;

enum PurposeTokenFailureReason: string
{
    case EXPIRED_TOKEN = 'expired_token';

    case INVALID_TOKEN = 'invalid_token';

    case KEY_NOT_USABLE = 'key_not_usable';

    case NOT_YET_VALID = 'not_yet_valid';

    case UNSUPPORTED_FORMAT = 'unsupported_format';

    case WRONG_CONTEXT = 'wrong_context';

    case WRONG_PURPOSE = 'wrong_purpose';
}
