<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial\Enum;

enum HkdfAlgorithm: string
{
    case SHA256 = 'sha256';

    case SHA384 = 'sha384';

    case SHA512 = 'sha512';
}
