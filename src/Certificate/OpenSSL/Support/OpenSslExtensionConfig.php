<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL\Support;

use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Exception\ConfigurationException;

/**
 * @internal
 */
final class OpenSslExtensionConfig
{
    /**
     * @param array<array-key, mixed> $distinguishedName
     */
    public static function createTempConfig(CertificateOptions $options, array $distinguishedName = []): string
    {
        $validatedDistinguishedName = [];
        foreach ($distinguishedName as $key => $value) {
            if (!is_string($key) || !is_string($value)) {
                throw new ConfigurationException('OpenSSL distinguished name values must be strings.');
            }
            self::assertConfigValue($value, 'distinguished name');
            $validatedDistinguishedName[$key] = $value;
        }
        $commonName = self::resolveCommonName($validatedDistinguishedName);

        $lines = [
            '[req]',
            'distinguished_name=req_distinguished_name',
            'prompt=no',
            'req_extensions=v3_req',
            'x509_extensions=v3_req',
            '',
            '[req_distinguished_name]',
            sprintf('CN=%s', $commonName),
            '',
            '[v3_req]',
        ];

        $sanEntries = self::sanEntries($options);

        if ($sanEntries !== []) {
            $lines[] = 'subjectAltName=@alt_names';
        }

        if ($options->keyUsage !== []) {
            $lines[] = 'keyUsage=' . implode(', ', array_map(static fn($usage): string => $usage->value, $options->keyUsage));
        }

        if ($options->extendedKeyUsage !== []) {
            $lines[] = 'extendedKeyUsage=' . implode(', ', array_map(static fn($usage): string => $usage->value, $options->extendedKeyUsage));
        }

        $lines[] = 'basicConstraints=' . ($options->isCa ? 'critical,CA:TRUE' : 'CA:FALSE');

        if ($sanEntries !== []) {
            $lines[] = '';
            $lines[] = '[alt_names]';
            array_push($lines, ...$sanEntries);
        }

        $tempFile = tempnam(sys_get_temp_dir(), 'epicrypt-openssl-');
        if ($tempFile === false) {
            throw new ConfigurationException('Unable to create OpenSSL extension config.');
        }

        if (file_put_contents($tempFile, implode(PHP_EOL, $lines) . PHP_EOL) === false) {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }

            throw new ConfigurationException('Unable to write OpenSSL extension config.');
        }

        return $tempFile;
    }

    private static function assertConfigValue(string $value, string $label): void
    {
        if (str_contains($value, "\r") || str_contains($value, "\n") || str_contains($value, "\0")) {
            throw new ConfigurationException(sprintf('OpenSSL %s cannot contain CR, LF, or NUL.', $label));
        }
    }

    /**
     * @param array<string, string> $distinguishedName
     */
    private static function resolveCommonName(array $distinguishedName): string
    {
        $commonName = $distinguishedName['commonName'] ?? $distinguishedName['CN'] ?? null;
        if (!is_string($commonName)) {
            return 'localhost';
        }

        $trimmed = trim($commonName);

        return $trimmed === '' ? 'localhost' : $trimmed;
    }

    /** @return list<string> */
    private static function sanEntries(CertificateOptions $options): array
    {
        $entries = [];
        foreach ($options->sanDns as $index => $dns) {
            $entries[] = sprintf('DNS.%d=%s', $index + 1, $dns);
        }
        foreach ($options->sanIp as $index => $ip) {
            $entries[] = sprintf('IP.%d=%s', $index + 1, $ip);
        }
        foreach ($options->sanEmail as $index => $email) {
            $entries[] = sprintf('email.%d=%s', $index + 1, $email);
        }

        return $entries;
    }
}
