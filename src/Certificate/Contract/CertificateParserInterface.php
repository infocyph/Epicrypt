<?php

namespace Infocyph\Epicrypt\Certificate\Contract;

interface CertificateParserInterface
{
    /**
     * @return array<string, mixed>
     */
    public function parse(string $certificatePem): array;
}
