<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Contract\KeyPairGeneratorInterface;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;

final readonly class KeyPairGenerator implements KeyPairGeneratorInterface
{
    public function __construct(
        private OpenSslRsaBits $bits = OpenSslRsaBits::BITS_3072,
        private OpenSslKeyType $type = OpenSslKeyType::RSA,
        private ?OpenSslCurveName $curveName = null,
    ) {}

    /**
     * @return array{private: string, public: string}
     */
    public function generate(?string $passphrase = null, bool $asBase64Url = false): array
    {
        $config = [
            'private_key_bits' => $this->bits->value,
            'private_key_type' => $this->type->value,
        ];

        if ($this->curveName !== null) {
            $config['curve_name'] = $this->curveName->value;
        }

        try {
            return $this->generateWithConfig($config, $passphrase, $asBase64Url);
        } catch (ConfigurationException $exception) {
            if (!$this->shouldFallbackToTempConfig($exception)) {
                throw $exception;
            }
        }

        $tempConfigPath = $this->createTempOpenSslConfig();
        $config['config'] = $tempConfigPath;

        try {
            return $this->generateWithConfig($config, $passphrase, $asBase64Url);
        } finally {
            if (file_exists($tempConfigPath)) {
                unlink($tempConfigPath);
            }
        }
    }

    /**
     * @param list<string> $errors
     */
    private function buildOpenSslFailureMessage(string $message, array $errors): string
    {
        if ($errors === []) {
            return $message;
        }

        return $message . ' OpenSSL errors: ' . implode(' | ', $errors);
    }

    private function createTempOpenSslConfig(): string
    {
        $tempFile = tempnam(sys_get_temp_dir(), 'epicrypt-openssl-keygen-');
        if ($tempFile === false) {
            throw new ConfigurationException('Unable to create OpenSSL key generation config.');
        }

        $content = "[req]\n"
            . "distinguished_name=req_distinguished_name\n"
            . "prompt=no\n\n"
            . "[req_distinguished_name]\n"
            . "CN=localhost\n";

        if (file_put_contents($tempFile, $content) === false) {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }

            throw new ConfigurationException('Unable to write OpenSSL key generation config.');
        }

        return $tempFile;
    }

    /**
     * @return list<string>
     */
    private function drainOpenSslErrors(): array
    {
        $errors = [];
        while (true) {
            $error = openssl_error_string();
            if (!is_string($error)) {
                break;
            }

            $errors[] = $error;
        }

        return $errors;
    }

    /**
     * @param array<string, int|string> $config
     * @return array{private: string, public: string}
     */
    private function generateWithConfig(array $config, ?string $passphrase, bool $asBase64Url): array
    {
        $this->drainOpenSslErrors();

        $resource = openssl_pkey_new($config);
        if ($resource === false) {
            throw new ConfigurationException($this->buildOpenSslFailureMessage(
                'OpenSSL key pair generation failed.',
                $this->drainOpenSslErrors(),
            ));
        }

        $privateKey = null;
        $exported = openssl_pkey_export($resource, $privateKey, $passphrase ?? '', $config);
        if (!$exported || !is_string($privateKey) || $privateKey === '') {
            throw new ConfigurationException($this->buildOpenSslFailureMessage(
                'Failed to export private key.',
                $this->drainOpenSslErrors(),
            ));
        }

        $details = openssl_pkey_get_details($resource);
        if (!is_array($details) || !isset($details['key']) || !is_string($details['key']) || $details['key'] === '') {
            throw new ConfigurationException($this->buildOpenSslFailureMessage(
                'Failed to export public key.',
                $this->drainOpenSslErrors(),
            ));
        }

        if (!$asBase64Url) {
            return ['private' => $privateKey, 'public' => $details['key']];
        }

        return [
            'private' => Base64Url::encode($privateKey),
            'public' => Base64Url::encode($details['key']),
        ];
    }

    private function shouldFallbackToTempConfig(ConfigurationException $exception): bool
    {
        $message = strtolower($exception->getMessage());

        return str_contains($message, 'configuration file routines')
            || str_contains($message, 'unable to load config info')
            || str_contains($message, 'bio routines')
            || str_contains($message, 'no such file');
    }
}
