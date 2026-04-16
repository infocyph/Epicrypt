<?php

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Contract\CertificateBuilderInterface;
use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class CertificateBuilder implements CertificateBuilderInterface
{
    public function __construct(
        private string $digestAlgorithm = 'sha512',
    ) {}

    /**
     * @param array<string, string> $distinguishedName
     */
    public function selfSign(array $distinguishedName, string $privateKey, int $days = 365, ?string $passphrase = null): string
    {
        $privateResource = Pem::requirePrivateKeyResource($privateKey, $passphrase);

        $csr = openssl_csr_new($distinguishedName, $privateResource, ['digest_alg' => $this->digestAlgorithm]);
        if ($csr === false) {
            throw new ConfigurationException('CSR generation failed for certificate signing.');
        }

        $certificate = openssl_csr_sign($csr, null, $privateResource, $days, ['digest_alg' => $this->digestAlgorithm]);
        if ($certificate === false) {
            throw new ConfigurationException('Certificate signing failed.');
        }

        $exported = openssl_x509_export($certificate, $certificatePem);
        if (! $exported || ! is_string($certificatePem) || $certificatePem === '') {
            throw new ConfigurationException('Certificate export failed.');
        }

        return $certificatePem;
    }
}
