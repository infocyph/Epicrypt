<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

final class PemNormalizer
{
    public function normalize(string $pem): string
    {
        $normalized = str_replace(["\r\n", "\r"], "\n", trim($pem));

        return $normalized . "\n";
    }
}
