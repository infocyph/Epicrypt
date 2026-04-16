<?php

namespace Infocyph\Epicrypt\Integrity\Contract;

interface HasherInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function hash(string $data, array $options = []): string;

    /**
     * @param array<string, mixed> $options
     */
    public function verify(string $data, string $digest, array $options = []): bool;
}
