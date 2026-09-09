<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

enum PersonalAccessTokenValidationStatus: string
{
    case VALID = 'valid';

    case INVALID = 'invalid';

    case INACTIVE = 'inactive';

    case STATE_MISMATCH = 'state_mismatch';
}
