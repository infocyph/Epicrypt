<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\Enum\CertificateDigest;
use Infocyph\Epicrypt\Certificate\OpenSSL\Support\OpenSslCertificateSigner;
use Infocyph\Epicrypt\Certificate\OpenSSL\Support\OpenSslExtensionConfig;
use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class CertificateBuilder
{
    public function __construct(
        private CertificateDigest $digestAlgorithm = CertificateDigest::SHA512,
    ) {}

    /**
     * @param array<string, string> $distinguishedName
     */
    public function selfSign(
        array $distinguishedName,
        #[\SensitiveParameter]
        string $privateKey,
        int $days = 365,
        #[\SensitiveParameter]
        ?string $passphrase = null,
        ?CertificateOptions $options = null,
    ): string {
        $privateResource = Pem::requirePrivateKeyResource($privateKey, $passphrase);
        $effectiveOptions = $options ?? new CertificateOptions(days: $days, digestAlgorithm: $this->digestAlgorithm);
        $requestedDays = $effectiveOptions->days;
        $digestAlgorithm = $effectiveOptions->digestAlgorithm->value;
        $tempConfigPath = OpenSslExtensionConfig::createTempConfig($effectiveOptions, $distinguishedName);
        $csrConfig = ['digest_alg' => $digestAlgorithm];
        $signConfig = ['digest_alg' => $digestAlgorithm];
        $csrConfig['config'] = $tempConfigPath;
        $csrConfig['req_extensions'] = 'v3_req';
        $signConfig['config'] = $tempConfigPath;
        $signConfig['x509_extensions'] = 'v3_req';

        try {
            $csr = openssl_csr_new($distinguishedName, $privateResource, $csrConfig);
            if (!$csr instanceof \OpenSSLCertificateSigningRequest) {
                throw new ConfigurationException('CSR generation failed for certificate signing.');
            }

            $signingPrivateKey = $passphrase === null ? $privateKey : [$privateKey, $passphrase];

            return OpenSslCertificateSigner::signAndExport(
                $csr,
                null,
                $signingPrivateKey,
                $requestedDays,
                $signConfig,
                'Certificate signing failed.',
                'Certificate export failed.',
            );
        } finally {
            if (file_exists($tempConfigPath)) {
                unlink($tempConfigPath);
            }
        }
    }
}
