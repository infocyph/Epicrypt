<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Enum;

enum CertificateDigest: string
{
    case SHA256 = 'sha256';

    case SHA384 = 'sha384';

    case SHA512 = 'sha512';
}
