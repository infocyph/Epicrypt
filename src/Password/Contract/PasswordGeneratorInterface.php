<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Contract;

interface PasswordGeneratorInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function generate(int $length = 16, array $options = []): string;
}
