<?php

namespace Infocyph\Epicrypt\Contract;

interface PasswordGeneratorInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function generate(int $length = 16, array $options = []): string;
}
