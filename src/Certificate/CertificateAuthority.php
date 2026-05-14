<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Contract\CertificateAuthorityInterface;

final readonly class CertificateAuthority implements CertificateAuthorityInterface
{
    public function __construct(
        private CertificateAuthorityInterface $backend,
    ) {}

    public static function openSsl(): self
    {
        return new self(new OpenSSL\CertificateAuthority());
    }

    public function signCsr(
        string $csrPem,
        string $caCertificatePem,
        string $caPrivateKeyPem,
        CertificateOptions $options,
        ?string $passphrase = null,
    ): string {
        return $this->backend->signCsr($csrPem, $caCertificatePem, $caPrivateKeyPem, $options, $passphrase);
    }
}
