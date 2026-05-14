<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

use Infocyph\Epicrypt\Password\Contract\CompromisedPasswordCheckerInterface;

final class NullCompromisedPasswordChecker implements CompromisedPasswordCheckerInterface
{
    public function isCompromised(string $password): bool
    {
        unset($password);

        return false;
    }
}
