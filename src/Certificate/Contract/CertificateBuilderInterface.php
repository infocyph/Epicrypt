<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Contract;

use Infocyph\Epicrypt\Certificate\CertificateOptions;

interface CertificateBuilderInterface
{
    /**
     * @param array<string, string> $distinguishedName
     */
    public function selfSign(array $distinguishedName, string $privateKey, int $days = 365, ?string $passphrase = null, ?CertificateOptions $options = null): string;
}
