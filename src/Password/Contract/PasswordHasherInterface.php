<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Contract;

interface PasswordHasherInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function hashPassword(#[\SensitiveParameter] string $password, array $options = []): string;

    /**
     * @param array<string, mixed> $options
     */
    public function verifyPassword(#[\SensitiveParameter] string $password, string $hash, array $options = []): bool;
}
