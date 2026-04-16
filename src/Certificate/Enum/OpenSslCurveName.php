<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Enum;

enum OpenSslCurveName: string
{
    case PRIME256V1 = 'prime256v1';
    case SECP384R1 = 'secp384r1';
    case SECP521R1 = 'secp521r1';

    public static function recommended(): self
    {
        return self::PRIME256V1;
    }
}
