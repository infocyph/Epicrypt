<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Enum;

enum KeyExchangeBackend: string
{
    case OPENSSL = 'openssl';

    case SODIUM = 'sodium';
}
