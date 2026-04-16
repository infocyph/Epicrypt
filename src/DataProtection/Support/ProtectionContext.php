<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;

/**
 * @internal
 */
final class ProtectionContext
{
    /**
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    public static function normalize(array $context): array
    {
        $keyIsBinary = $context['key_is_binary'] ?? false;
        if (!is_bool($keyIsBinary)) {
            throw new ConfigurationException('Protection context key_is_binary must be a boolean.');
        }

        $nonceIsBinary = $context['nonce_is_binary'] ?? false;
        if (!is_bool($nonceIsBinary)) {
            throw new ConfigurationException('Protection context nonce_is_binary must be a boolean.');
        }

        $aad = $context['aad'] ?? '';
        if (!is_string($aad)) {
            throw new ConfigurationException('Protection context aad must be a string.');
        }

        $context['key_is_binary'] = $keyIsBinary;
        $context['nonce_is_binary'] = $nonceIsBinary;
        $context['aad'] = $aad;

        return $context;
    }
}
