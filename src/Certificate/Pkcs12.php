<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class Pkcs12
{
    /**
     * @param list<string> $caCertificatesPem
     */
    public function export(
        string $certificatePem,
        #[\SensitiveParameter]
        string $privateKeyPem,
        #[\SensitiveParameter]
        string $password,
        #[\SensitiveParameter]
        ?string $privateKeyPassphrase = null,
        ?string $friendlyName = null,
        array $caCertificatesPem = [],
    ): string {
        $certificate = openssl_x509_read($certificatePem);
        if ($certificate === false) {
            throw new ConfigurationException('Invalid certificate for PKCS#12 export.');
        }

        $privateKey = Pem::requirePrivateKeyResource($privateKeyPem, $privateKeyPassphrase);
        $options = [];
        if ($friendlyName !== null && $friendlyName !== '') {
            $options['friendly_name'] = $friendlyName;
        }
        if ($caCertificatesPem !== []) {
            $options['extracerts'] = implode(PHP_EOL, $caCertificatesPem);
        }

        $pkcs12 = '';
        $ok = openssl_pkcs12_export(
            $certificate,
            $pkcs12,
            $privateKey,
            $password,
            $options,
        );

        if (!$ok || !is_string($pkcs12) || $pkcs12 === '') {
            throw new ConfigurationException('PKCS#12 export failed.');
        }

        return $pkcs12;
    }

    /**
     * @return array{certificate: string, private_key: string, ca_certificates: list<string>}
     */
    public function import(
        #[\SensitiveParameter]
        string $pkcs12,
        #[\SensitiveParameter]
        string $password,
    ): array {
        $output = [];
        if (!openssl_pkcs12_read($pkcs12, $output, $password)) {
            throw new ConfigurationException('PKCS#12 import failed.');
        }
        if (!is_array($output)) {
            throw new ConfigurationException('PKCS#12 import produced invalid output.');
        }

        $certificate = $output['cert'] ?? null;
        $privateKey = $output['pkey'] ?? null;
        if (!is_string($certificate) || $certificate === '' || !is_string($privateKey) || $privateKey === '') {
            throw new ConfigurationException('PKCS#12 payload is missing certificate or private key.');
        }

        $extra = $output['extracerts'] ?? [];
        $caCertificates = [];
        if (is_array($extra)) {
            foreach ($extra as $entry) {
                if (is_string($entry) && $entry !== '') {
                    $caCertificates[] = $entry;
                }
            }
        }

        return [
            'certificate' => $certificate,
            'private_key' => $privateKey,
            'ca_certificates' => $caCertificates,
        ];
    }
}
