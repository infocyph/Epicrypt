<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

enum KeyStatus
{
    case ACTIVE;

    case DISABLED;

    case FALLBACK;

    case RETIRED;
}
