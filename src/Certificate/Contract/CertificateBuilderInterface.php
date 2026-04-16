<?php

namespace Infocyph\Epicrypt\Certificate\Contract;

interface CertificateBuilderInterface
{
    /**
     * @param array<string, string> $distinguishedName
     */
    public function selfSign(array $distinguishedName, string $privateKey, int $days = 365, ?string $passphrase = null): string;
}
