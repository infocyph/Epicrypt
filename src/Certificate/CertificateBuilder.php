<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Contract\CertificateBuilderInterface;

final readonly class CertificateBuilder implements CertificateBuilderInterface
{
    public function __construct(
        private CertificateBuilderInterface $backend,
    ) {}

    public static function openSsl(string $digestAlgorithm = 'sha512'): self
    {
        return new self(new OpenSSL\CertificateBuilder($digestAlgorithm));
    }

    /**
     * @param array<string, string> $distinguishedName
     */
    public function selfSign(array $distinguishedName, string $privateKey, int $days = 365, ?string $passphrase = null): string
    {
        return $this->backend->selfSign($distinguishedName, $privateKey, $days, $passphrase);
    }
}
