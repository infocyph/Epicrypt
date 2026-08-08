<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

enum KeyPurpose
{
    case DATA_PROTECTION;

    case ENVELOPE_PROTECTION;

    case FILE_PROTECTION;

    case JWT_SIGNING;

    case KEY_ROTATION;

    case SECRET_WRAPPING;

    case SIGNED_PAYLOAD;
}
