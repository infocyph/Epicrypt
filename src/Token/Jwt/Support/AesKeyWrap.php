<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;

/** @internal RFC 3394 composition over OpenSSL AES-256-ECB. */
final class AesKeyWrap
{
    private const string IV = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";

    public function unwrap(#[\SensitiveParameter] string $keyEncryptionKey, #[\SensitiveParameter] string $wrapped): string
    {
        $this->validate($keyEncryptionKey, $wrapped, true);
        $a = substr($wrapped, 0, 8);
        $blocks = str_split(substr($wrapped, 8), 8);
        $count = count($blocks);
        for ($round = 5; $round >= 0; $round--) {
            for ($index = $count - 1; $index >= 0; $index--) {
                $decrypted = $this->decryptBlock($keyEncryptionKey, ($a ^ $this->counter(($count * $round) + $index + 1)) . $blocks[$index]);
                $a = substr($decrypted, 0, 8);
                $blocks[$index] = substr($decrypted, 8, 8);
            }
        }
        if (!hash_equals(self::IV, $a)) {
            throw new InvalidTokenException('JWE AES key unwrap integrity check failed.');
        }

        return implode('', $blocks);
    }

    public function wrap(#[\SensitiveParameter] string $keyEncryptionKey, #[\SensitiveParameter] string $key): string
    {
        $this->validate($keyEncryptionKey, $key, false);
        $blocks = str_split($key, 8);
        $a = self::IV;
        $count = count($blocks);
        for ($round = 0; $round < 6; $round++) {
            for ($index = 0; $index < $count; $index++) {
                $encrypted = $this->encryptBlock($keyEncryptionKey, $a . $blocks[$index]);
                $a = substr($encrypted, 0, 8) ^ $this->counter(($count * $round) + $index + 1);
                $blocks[$index] = substr($encrypted, 8, 8);
            }
        }

        return $a . implode('', $blocks);
    }

    private function counter(int $value): string
    {
        return pack('N2', 0, $value);
    }

    private function decryptBlock(string $key, string $block): string
    {
        $result = openssl_decrypt($block, 'aes-256-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        if (!is_string($result) || strlen($result) !== 16) {
            throw new InvalidTokenException('JWE AES key unwrap failed.');
        }

        return $result;
    }

    private function encryptBlock(string $key, string $block): string
    {
        $result = openssl_encrypt($block, 'aes-256-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        if (!is_string($result) || strlen($result) !== 16) {
            throw new InvalidTokenException('JWE AES key wrap failed.');
        }

        return $result;
    }

    private function validate(string $keyEncryptionKey, string $value, bool $wrapped): void
    {
        $minimum = $wrapped ? 24 : 16;
        if (strlen($keyEncryptionKey) !== 32 || strlen($value) < $minimum || strlen($value) % 8 !== 0) {
            throw new InvalidTokenException('JWE AES key-wrap input has an invalid size.');
        }
    }
}
