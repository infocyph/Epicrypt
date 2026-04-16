<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Enum;

enum OpenSslRsaBits: int
{
    case BITS_1024 = 1024;

    case BITS_2048 = 2048;

    case BITS_3072 = 3072;

    case BITS_4096 = 4096;

    case BITS_8192 = 8192;
}
