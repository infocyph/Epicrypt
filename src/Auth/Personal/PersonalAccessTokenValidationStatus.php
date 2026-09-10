<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

enum PersonalAccessTokenValidationStatus: string
{
    case INACTIVE = 'inactive';

    case INVALID = 'invalid';

    case STATE_MISMATCH = 'state_mismatch';

    case VALID = 'valid';
}
