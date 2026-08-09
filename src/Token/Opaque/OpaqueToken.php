<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Opaque;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class OpaqueToken
{
    public const int DEFAULT_LENGTH = 48;

    public const int MAXIMUM_LENGTH = 128;

    public const int MINIMUM_LENGTH = 43;

    public function hash(#[\SensitiveParameter] string $token): string
    {
        self::assertToken($token);

        return sodium_bin2hex(sodium_crypto_generichash($token));
    }

    public function issue(int $length = self::DEFAULT_LENGTH): string
    {
        if ($length < self::MINIMUM_LENGTH || $length > self::MAXIMUM_LENGTH) {
            throw new ConfigurationException(sprintf(
                'Opaque token length must contain between %d and %d characters.',
                self::MINIMUM_LENGTH,
                self::MAXIMUM_LENGTH,
            ));
        }
        $bytes = random_bytes($length);
        $encoded = rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

        return substr($encoded, 0, $length);
    }

    public function verify(#[\SensitiveParameter] string $token, #[\SensitiveParameter] string $digest): bool
    {
        if (!self::isToken($token) || preg_match('/\A[a-f0-9]{64}\z/D', $digest) !== 1) {
            return false;
        }

        return hash_equals($digest, $this->hash($token));
    }

    private static function assertToken(string $token): void
    {
        if (!self::isToken($token)) {
            throw new ConfigurationException(sprintf(
                'Opaque tokens must contain %d to %d Base64URL characters.',
                self::MINIMUM_LENGTH,
                self::MAXIMUM_LENGTH,
            ));
        }
    }

    private static function isToken(string $token): bool
    {
        $length = strlen($token);

        return $length >= self::MINIMUM_LENGTH
            && $length <= self::MAXIMUM_LENGTH
            && preg_match('/\A[A-Za-z0-9_-]+\z/D', $token) === 1;
    }
}
