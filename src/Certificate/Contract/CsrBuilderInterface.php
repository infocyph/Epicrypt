<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Contract;

interface CsrBuilderInterface
{
    /**
     * @param array<string, string> $distinguishedName
     */
    public function build(array $distinguishedName, string $privateKey, ?string $passphrase = null): string;
}
