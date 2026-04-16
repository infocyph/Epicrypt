<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal\Enum;

enum SignedPayloadAlgorithm: string
{
    case SHA256 = 'sha256';
    case SHA512 = 'sha512';
}
