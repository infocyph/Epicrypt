<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;

final readonly class CertificateExpiry
{
    public function __construct(private ClockInterface $clock = new SystemClock()) {}

    public function expiresAt(string $certificatePem): int
    {
        $parsed = openssl_x509_parse($certificatePem, false);
        if (!is_array($parsed) || !isset($parsed['validTo_time_t']) || !is_int($parsed['validTo_time_t'])) {
            throw new ConfigurationException('Unable to parse certificate expiration.');
        }

        return $parsed['validTo_time_t'];
    }

    public function isExpired(string $certificatePem, int $leewaySeconds = 0): bool
    {
        if ($leewaySeconds < 0) {
            throw new ConfigurationException('Certificate expiry leeway must not be negative.');
        }

        return $this->clock->now()->getTimestamp() + $leewaySeconds >= $this->expiresAt($certificatePem);
    }
}
