<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Enum;

enum JweContentEncryptionAlgorithm: string
{
    case A256GCM = 'A256GCM';
}
