<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Sodium\Support;

use Infocyph\Epicrypt\Internal\Base64Url;

final class SodiumKeyPairFactory
{
    /**
     * @param callable(): string $createKeyPair
     * @param callable(string): string $extractPrivate
     * @param callable(string): string $extractPublic
     * @return array{private: string, public: string}
     */
    public static function generate(
        callable $createKeyPair,
        callable $extractPrivate,
        callable $extractPublic,
        bool $asBase64Url,
    ): array {
        $keypair = $createKeyPair();
        $private = $extractPrivate($keypair);
        $public = $extractPublic($keypair);

        if (!$asBase64Url) {
            return ['private' => $private, 'public' => $public];
        }

        return ['private' => Base64Url::encode($private), 'public' => Base64Url::encode($public)];
    }
}
