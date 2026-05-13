<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Contract;

use Infocyph\Epicrypt\Certificate\CertificateOptions;

interface CertificateAuthorityInterface
{
    public function signCsr(
        string $csrPem,
        string $caCertificatePem,
        string $caPrivateKeyPem,
        CertificateOptions $options,
        ?string $passphrase = null,
    ): string;
}
