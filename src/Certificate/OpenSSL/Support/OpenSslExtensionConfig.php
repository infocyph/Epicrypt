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
    public static function createTempConfig(CertificateOptions $options): string
    {
        $lines = [
            '[req]',
            'distinguished_name=req_distinguished_name',
            'prompt=no',
            'req_extensions=v3_req',
            'x509_extensions=v3_req',
            '',
            '[req_distinguished_name]',
            'CN=localhost',
            '',
            '[v3_req]',
        ];

        $sanEntries = [];
        $dnsIndex = 1;
        foreach ($options->sanDns as $dns) {
            $sanEntries[] = sprintf('DNS.%d=%s', $dnsIndex++, $dns);
        }
        $ipIndex = 1;
        foreach ($options->sanIp as $ip) {
            $sanEntries[] = sprintf('IP.%d=%s', $ipIndex++, $ip);
        }
        $emailIndex = 1;
        foreach ($options->sanEmail as $email) {
            $sanEntries[] = sprintf('email.%d=%s', $emailIndex++, $email);
        }

        if ($sanEntries !== []) {
            $lines[] = 'subjectAltName=@alt_names';
        }

        if ($options->keyUsage !== []) {
            $lines[] = 'keyUsage=' . implode(', ', $options->keyUsage);
        }

        if ($options->extendedKeyUsage !== []) {
            $lines[] = 'extendedKeyUsage=' . implode(', ', $options->extendedKeyUsage);
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
}
