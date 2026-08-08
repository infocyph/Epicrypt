<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Integrity;

enum IntegrityAlgorithm: string
{
    case BLAKE2B = 'blake2b';

    case SHA256 = 'sha256';

    case SHA384 = 'sha384';

    case SHA512 = 'sha512';
}
