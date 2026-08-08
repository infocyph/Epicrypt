<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Enum\CertificateDigest;
use Infocyph\Epicrypt\Certificate\Enum\ExtendedKeyUsage;
use Infocyph\Epicrypt\Certificate\Enum\KeyUsage;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class CertificateOptions
{
    /** @var list<ExtendedKeyUsage> */
    public array $extendedKeyUsage;

    /** @var list<KeyUsage> */
    public array $keyUsage;

    /** @var list<string> */
    public array $sanDns;

    /** @var list<string> */
    public array $sanEmail;

    /** @var list<string> */
    public array $sanIp;

    /**
     * @param array<array-key, mixed> $sanDns
     * @param array<array-key, mixed> $sanIp
     * @param array<array-key, mixed> $sanEmail
     * @param array<array-key, mixed> $keyUsage
     * @param array<array-key, mixed> $extendedKeyUsage
     */
    public function __construct(
        public int $days = 365,
        public CertificateDigest $digestAlgorithm = CertificateDigest::SHA512,
        array $sanDns = [],
        array $sanIp = [],
        array $sanEmail = [],
        array $keyUsage = [],
        array $extendedKeyUsage = [],
        public bool $isCa = false,
    ) {
        if ($this->days < 1 || $this->days > 3650) {
            throw new ConfigurationException('Certificate lifetime must be between 1 and 3650 days.');
        }

        $this->sanDns = $this->validateDnsNames($sanDns);
        $this->sanIp = $this->validateIpAddresses($sanIp);
        $this->sanEmail = $this->validateEmailAddresses($sanEmail);
        $this->keyUsage = $this->validateKeyUsages($keyUsage);
        $this->extendedKeyUsage = $this->validateExtendedKeyUsages($extendedKeyUsage);
    }

    /** @param array<array-key, mixed> $values */
    private function assertList(array $values): void
    {
        if (!array_is_list($values)) {
            throw new ConfigurationException('Certificate option collections must be lists.');
        }
    }

    private function containsConfigControl(string $value): bool
    {
        return str_contains($value, "\r") || str_contains($value, "\n") || str_contains($value, "\0");
    }

    /**
     * @param array<array-key, mixed> $values
     * @return list<string>
     */
    private function validateDnsNames(array $values): array
    {
        $this->assertList($values);
        $validated = [];
        foreach ($values as $dns) {
            if (!is_string($dns) || !$this->validDnsName($dns)) {
                throw new ConfigurationException('Invalid DNS subject alternative name.');
            }
            $validated[] = $dns;
        }

        return $validated;
    }

    /**
     * @param array<array-key, mixed> $values
     * @return list<string>
     */
    private function validateEmailAddresses(array $values): array
    {
        $this->assertList($values);
        $validated = [];
        foreach ($values as $email) {
            if (!is_string($email)
                || filter_var($email, FILTER_VALIDATE_EMAIL) === false
                || $this->containsConfigControl($email)) {
                throw new ConfigurationException('Invalid email subject alternative name.');
            }
            $validated[] = $email;
        }

        return $validated;
    }

    /**
     * @param array<array-key, mixed> $values
     * @return list<ExtendedKeyUsage>
     */
    private function validateExtendedKeyUsages(array $values): array
    {
        $this->assertList($values);
        $validated = [];
        foreach ($values as $usage) {
            if (!$usage instanceof ExtendedKeyUsage) {
                throw new ConfigurationException('Certificate extended key usages must use the ExtendedKeyUsage enum.');
            }
            $validated[] = $usage;
        }

        return $validated;
    }

    /**
     * @param array<array-key, mixed> $values
     * @return list<string>
     */
    private function validateIpAddresses(array $values): array
    {
        $this->assertList($values);
        $validated = [];
        foreach ($values as $ip) {
            if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
                throw new ConfigurationException('Invalid IP subject alternative name.');
            }
            $validated[] = $ip;
        }

        return $validated;
    }

    /**
     * @param array<array-key, mixed> $values
     * @return list<KeyUsage>
     */
    private function validateKeyUsages(array $values): array
    {
        $this->assertList($values);
        $validated = [];
        foreach ($values as $usage) {
            if (!$usage instanceof KeyUsage) {
                throw new ConfigurationException('Certificate key usages must use the KeyUsage enum.');
            }
            $validated[] = $usage;
        }

        return $validated;
    }

    private function validDnsName(string $name): bool
    {
        if ($name === '' || strlen($name) > 253 || $this->containsConfigControl($name)) {
            return false;
        }

        $candidate = str_starts_with($name, '*.') ? substr($name, 2) : $name;

        return array_all(explode('.', $candidate), fn($label) => !($label === '' || strlen($label) > 63 || preg_match('/\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\z/D', $label) !== 1));
    }
}
