<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Contract;

interface CompromisedPasswordCheckerInterface
{
    public function isCompromised(string $password): bool;
}
