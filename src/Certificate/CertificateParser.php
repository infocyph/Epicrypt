<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Contract\CertificateParserInterface;

final readonly class CertificateParser implements CertificateParserInterface
{
    public function __construct(
        private CertificateParserInterface $backend,
    ) {}

    public static function openSsl(): self
    {
        return new self(new OpenSSL\CertificateParser());
    }

    /**
     * @return array<string, mixed>
     */
    public function parse(string $certificatePem): array
    {
        return $this->backend->parse($certificatePem);
    }
}
