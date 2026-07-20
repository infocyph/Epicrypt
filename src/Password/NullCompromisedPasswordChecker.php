<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

use Infocyph\Epicrypt\Password\Contract\CompromisedPasswordCheckerInterface;

final class NullCompromisedPasswordChecker implements CompromisedPasswordCheckerInterface
{
    // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter -- The null implementation intentionally performs no lookup.
    public function isCompromised(#[\SensitiveParameter] string $password): bool
    {
        return false;
    }
}
