<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class ProtectionAad
{
    public static function forEnvelope(string $purpose, string $version): string
    {
        return self::build('envelope', $purpose, $version);
    }

    public static function forFile(string $purpose, string $version): string
    {
        return self::build('file', $purpose, $version);
    }

    public static function forString(string $purpose, string $version): string
    {
        return self::build('string', $purpose, $version);
    }

    private static function build(string $scope, string $purpose, string $version): string
    {
        if ($purpose === '' || $version === '') {
            throw new ConfigurationException('AAD purpose and version must be non-empty strings.');
        }

        return sprintf('epicrypt:%s:%s:%s', $scope, $purpose, $version);
    }
}
