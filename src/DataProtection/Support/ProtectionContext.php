<?php

namespace Infocyph\Epicrypt\DataProtection\Support;

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
        $context['key_is_binary'] = (bool) ($context['key_is_binary'] ?? false);
        $context['nonce_is_binary'] = (bool) ($context['nonce_is_binary'] ?? false);
        $context['aad'] = (string) ($context['aad'] ?? '');

        return $context;
    }
}
