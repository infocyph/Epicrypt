<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

final readonly class CertificateOptions
{
    /**
     * @param list<string> $sanDns
     * @param list<string> $sanIp
     * @param list<string> $sanEmail
     * @param list<string> $keyUsage
     * @param list<string> $extendedKeyUsage
     */
    public function __construct(
        public int $days = 365,
        public string $digestAlgorithm = 'sha512',
        public array $sanDns = [],
        public array $sanIp = [],
        public array $sanEmail = [],
        public array $keyUsage = [],
        public array $extendedKeyUsage = [],
        public bool $isCa = false,
    ) {}
}
