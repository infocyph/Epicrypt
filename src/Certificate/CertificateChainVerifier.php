<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Enum\CertificatePurpose;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use phpseclib4\File\X509;
use Throwable;

final class CertificateChainVerifier
{
    private const int MAX_CERTIFICATE_BYTES = 1_048_576;

    private const int MAX_TRUST_ANCHORS = 32;

    private const int MAX_INTERMEDIATES = 16;

    /**
     * @param list<string> $trustedCaCertificatesPem
     * @param list<string> $intermediateCertificatesPem
     */
    public function verify(
        string $certificatePem,
        array $trustedCaCertificatesPem,
        CertificatePurpose $purpose = CertificatePurpose::SSL_SERVER,
        array $intermediateCertificatesPem = [],
    ): bool {
        if ($trustedCaCertificatesPem === [] || count($trustedCaCertificatesPem) > self::MAX_TRUST_ANCHORS) {
            throw new ConfigurationException('Certificate chain requires between 1 and 32 trust anchors.');
        }
        if (count($intermediateCertificatesPem) > self::MAX_INTERMEDIATES) {
            throw new ConfigurationException('Certificate chain exceeds the intermediate certificate bound.');
        }

        $this->assertCertificate($certificatePem, 'leaf certificate');
        $seen = [hash('sha256', (new PemNormalizer())->normalize($certificatePem)) => true];
        $trustBundle = $this->bundle($trustedCaCertificatesPem, 'trust anchor', $seen);
        $intermediateBundle = $this->bundle($intermediateCertificatesPem, 'intermediate certificate', $seen);
        $trustPath = $this->writeBundle($trustBundle, 'epicrypt-ca-');
        $intermediatePath = $intermediateBundle === '' ? null : $this->writeBundle($intermediateBundle, 'epicrypt-chain-');

        try {
            $result = openssl_x509_checkpurpose(
                $certificatePem,
                $purpose->value,
                [$trustPath],
                $intermediatePath,
            );
            if ($result === false) {
                throw new ConfigurationException('Certificate chain verification failed to execute.');
            }

            return $result === true || $result === 1;
        } finally {
            $this->removeTempFile($trustPath);
            if ($intermediatePath !== null) {
                $this->removeTempFile($intermediatePath);
            }
        }
    }

    /**
     * @param list<string> $certificates
     * @param array<string, true> $seen
     */
    private function bundle(array $certificates, string $label, array &$seen): string
    {
        $bundle = '';
        foreach ($certificates as $certificate) {
            $this->assertCertificate($certificate, $label);
            $normalized = (new PemNormalizer())->normalize($certificate);
            $fingerprint = hash('sha256', $normalized);
            if (isset($seen[$fingerprint])) {
                throw new ConfigurationException(sprintf('Certificate chain contains a duplicate %s.', $label));
            }
            $seen[$fingerprint] = true;
            $bundle .= $normalized;
        }

        return $bundle;
    }

    private function assertCertificate(string $certificatePem, string $label): void
    {
        if ($certificatePem === '' || strlen($certificatePem) > self::MAX_CERTIFICATE_BYTES) {
            throw new ConfigurationException(sprintf('Certificate chain %s is empty or exceeds the size bound.', $label));
        }

        try {
            X509::load($certificatePem);
        } catch (Throwable $exception) {
            throw new ConfigurationException(sprintf('Certificate chain contains an invalid %s.', $label), 0, $exception);
        }
    }

    private function removeTempFile(string $path): void
    {
        if (is_file($path) && !unlink($path)) {
            clearstatcache(true, $path);
        }
    }

    private function writeBundle(string $bundle, string $prefix): string
    {
        $path = tempnam(sys_get_temp_dir(), $prefix);
        if ($path === false) {
            throw new ConfigurationException('Unable to allocate certificate chain staging file.');
        }
        if (!chmod($path, 0600) || file_put_contents($path, $bundle, LOCK_EX) === false) {
            @unlink($path);
            throw new ConfigurationException('Unable to write certificate chain staging file.');
        }

        return $path;
    }
}
