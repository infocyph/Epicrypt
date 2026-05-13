<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Contract;

use Infocyph\Epicrypt\Certificate\CertificateOptions;

interface CsrBuilderInterface
{
    /**
     * @param array<string, string> $distinguishedName
     */
    public function build(array $distinguishedName, string $privateKey, ?string $passphrase = null, ?CertificateOptions $options = null): string;
}
