<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use phpseclib4\Crypt\Common\PrivateKey;
use phpseclib4\Crypt\Common\PublicKey;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\File\PFX;
use phpseclib4\File\X509;
use Stringable;
use Throwable;

final class Pkcs12
{
    private const int MAX_CONTAINER_BYTES = 16_777_216;

    private const int MAX_CERTIFICATES = 64;

    private const int MAX_PEM_BYTES = 1_048_576;

    private const int MAX_PASSWORD_BYTES = 1024;

    /** @param list<string> $caCertificatesPem */
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
        $this->assertPemSize($certificatePem, 'certificate');
        $this->assertPemSize($privateKeyPem, 'private key');
        $this->assertPassword($password);
        if ($privateKeyPassphrase !== null) {
            $this->assertPassword($privateKeyPassphrase);
        }
        if ($friendlyName !== null && !$this->validFriendlyName($friendlyName)) {
            throw new ConfigurationException('PKCS#12 friendly name is invalid.');
        }
        if (count($caCertificatesPem) > self::MAX_CERTIFICATES - 1) {
            throw new ConfigurationException('PKCS#12 certificate count exceeds the configured bound.');
        }

        try {
            $certificate = X509::load($certificatePem);
            $privateKey = PublicKeyLoader::loadPrivateKey($privateKeyPem, $privateKeyPassphrase);
            if (!$privateKey instanceof PrivateKey) {
                throw new ConfigurationException('PKCS#12 requires a supported private key.');
            }
            $certificatePublicKey = $certificate->getPublicKey();
            if (!hash_equals($this->publicIdentity($certificatePublicKey), $this->publicIdentity($privateKey->getPublicKey()))) {
                throw new ConfigurationException('PKCS#12 certificate and private key do not match.');
            }

            $pfx = new PFX();
            $pfx->setPassword($password);
            $localKeyId = hash('sha256', $this->publicIdentity($certificatePublicKey), true);
            $pfx->add($certificate, friendlyName: $friendlyName, localKeyID: $localKeyId);
            $pfx->add($privateKey, friendlyName: $friendlyName, localKeyID: $localKeyId);
            foreach ($caCertificatesPem as $caCertificatePem) {
                $this->assertPemSize($caCertificatePem, 'CA certificate');
                $pfx->add(X509::load($caCertificatePem));
            }
            $encoded = $pfx->toString([
                'hashAlgorithm' => 'sha256',
                'iterationCount' => 2048,
                'saltLength' => 32,
            ]);
        } catch (ConfigurationException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new ConfigurationException('PKCS#12 export failed.', 0, $exception);
        }

        if ($encoded === '' || strlen($encoded) > self::MAX_CONTAINER_BYTES) {
            throw new ConfigurationException('PKCS#12 export exceeds the configured size bound.');
        }

        return $encoded;
    }

    /** @return array{certificate: string, private_key: string, ca_certificates: list<string>, friendly_names: list<string>} */
    public function import(
        #[\SensitiveParameter]
        string $pkcs12,
        #[\SensitiveParameter]
        string $password,
    ): array {
        if ($pkcs12 === '' || strlen($pkcs12) > self::MAX_CONTAINER_BYTES) {
            throw new ConfigurationException('PKCS#12 payload is empty or exceeds the configured size bound.');
        }
        $this->assertPassword($password);

        try {
            $pfx = PFX::load($pkcs12, $password);
            $certificates = $this->certificates($pfx->getCertificates());
            $privateKey = $this->singlePrivateKey($pfx->getPrivateKeys());
        } catch (ConfigurationException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new ConfigurationException('PKCS#12 import failed.', 0, $exception);
        }

        $publicIdentity = $this->publicIdentity($privateKey->getPublicKey());
        $certificate = null;
        $caCertificates = [];
        foreach ($certificates as $candidate) {
            $candidatePem = (string) $candidate;
            if ($certificate === null && hash_equals($publicIdentity, $this->publicIdentity($candidate->getPublicKey()))) {
                $certificate = $candidatePem;

                continue;
            }
            $caCertificates[] = $candidatePem;
        }
        if ($certificate === null) {
            throw new ConfigurationException('PKCS#12 private key has no matching certificate.');
        }

        $privateKeyPem = $privateKey->toString('PKCS8');
        $this->assertPemSize($certificate, 'certificate');
        $this->assertPemSize($privateKeyPem, 'private key');
        foreach ($caCertificates as $caCertificate) {
            $this->assertPemSize($caCertificate, 'CA certificate');
        }

        return [
            'certificate' => $certificate,
            'private_key' => $privateKeyPem,
            'ca_certificates' => $caCertificates,
            'friendly_names' => $this->friendlyNames($pfx->getFriendlyNames()),
        ];
    }

    private function assertPassword(#[\SensitiveParameter] string $password): void
    {
        if (strlen($password) > self::MAX_PASSWORD_BYTES) {
            throw new ConfigurationException('PKCS#12 password exceeds the configured size bound.');
        }
    }

    private function assertPemSize(string $pem, string $label): void
    {
        if ($pem === '' || strlen($pem) > self::MAX_PEM_BYTES) {
            throw new ConfigurationException(sprintf('PKCS#12 %s is empty or exceeds the configured size bound.', $label));
        }
    }

    /** @param array<array-key, mixed> $certificates @return list<X509> */
    private function certificates(array $certificates): array
    {
        if ($certificates === [] || count($certificates) > self::MAX_CERTIFICATES) {
            throw new ConfigurationException('PKCS#12 certificate set is empty or exceeds the configured bound.');
        }

        $result = [];
        foreach ($certificates as $certificate) {
            if (!$certificate instanceof X509) {
                throw new ConfigurationException('PKCS#12 contains an unsupported certificate entry.');
            }
            $result[] = $certificate;
        }

        return $result;
    }

    /** @param array<array-key, mixed> $names @return list<string> */
    private function friendlyNames(array $names): array
    {
        $result = [];
        foreach ($names as $name) {
            if (is_string($name)) {
                $result[] = $name;
            } elseif ($name instanceof Stringable) {
                $result[] = (string) $name;
            }
        }

        return array_values(array_unique($result));
    }

    private function publicIdentity(PublicKey $key): string
    {
        return $key->toString('PKCS8');
    }

    /** @param array<array-key, mixed> $privateKeys */
    private function singlePrivateKey(#[\SensitiveParameter] array $privateKeys): PrivateKey
    {
        if (count($privateKeys) !== 1 || !$privateKeys[0] instanceof PrivateKey) {
            throw new ConfigurationException('PKCS#12 must contain exactly one supported private key.');
        }

        return $privateKeys[0];
    }

    private function validFriendlyName(string $name): bool
    {
        return $name !== '' && strlen($name) <= 255 && preg_match('/[\x00-\x1F\x7F]/', $name) !== 1;
    }
}
