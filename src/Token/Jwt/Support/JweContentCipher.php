<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;

/** @internal JWE A256GCM content-encryption boundary. */
final class JweContentCipher
{
    public function decrypt(
        #[\SensitiveParameter]
        string $ciphertext,
        #[\SensitiveParameter]
        string $cek,
        string $aad,
        string $iv,
        string $tag,
    ): string {
        $this->requireKey($cek);
        if (strlen($iv) !== 12 || strlen($tag) !== 16) {
            throw new InvalidTokenException('JWE content IV or tag has an invalid size.');
        }
        $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $cek, OPENSSL_RAW_DATA, $iv, $tag, $aad);
        if (!is_string($plaintext)) {
            throw new InvalidTokenException('JWE authentication failed.');
        }

        return $plaintext;
    }

    /** @return array{ciphertext: string, iv: string, tag: string} */
    public function encrypt(#[\SensitiveParameter] string $plaintext, #[\SensitiveParameter] string $cek, string $aad): array
    {
        $this->requireKey($cek);
        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $cek, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
        if (!is_string($ciphertext) || strlen($tag) !== 16) {
            throw new InvalidTokenException('JWE content encryption failed.');
        }

        return ['ciphertext' => $ciphertext, 'iv' => $iv, 'tag' => $tag];
    }

    private function requireKey(string $cek): void
    {
        if (strlen($cek) !== 32) {
            throw new InvalidTokenException('JWE A256GCM requires a 256-bit content-encryption key.');
        }
    }
}
