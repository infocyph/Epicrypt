<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Enum;

enum JweKeyManagementAlgorithm: string
{
    case A256GCMKW = 'A256GCMKW';

    case A256KW = 'A256KW';

    case DIRECT = 'dir';

    case ECDH_ES = 'ECDH-ES';

    case ECDH_ES_A256KW = 'ECDH-ES+A256KW';

    case RSA_OAEP_256 = 'RSA-OAEP-256';
}
