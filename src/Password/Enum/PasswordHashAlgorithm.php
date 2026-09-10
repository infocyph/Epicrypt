<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Enum;

enum PasswordHashAlgorithm: string
{
    case ARGON2ID = 'argon2id';

    case BCRYPT = 'bcrypt';

    public function toPasswordAlgorithm(): string
    {
        return match ($this) {
            self::ARGON2ID => defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : 'argon2id',
            self::BCRYPT => defined('PASSWORD_BCRYPT') ? PASSWORD_BCRYPT : '2y',
        };
    }
}
