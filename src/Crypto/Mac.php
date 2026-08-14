<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;

final class Mac
{
    public function generate(string $message, #[\SensitiveParameter] string $key): string
    {
        $decodedKey = $this->decodeKey($key);

        return Base64Url::encode(sodium_crypto_auth($message, $decodedKey));
    }

    public function generateKey(bool $asBase64Url = true): string
    {
        $key = sodium_crypto_auth_keygen();

        return $asBase64Url ? Base64Url::encode($key) : $key;
    }

    public function generateWithBinaryKey(string $message, #[\SensitiveParameter] string $key): string
    {
        $this->assertBinaryKey($key);

        return Base64Url::encode(sodium_crypto_auth($message, $key));
    }

    public function verify(string $message, string $mac, #[\SensitiveParameter] string $key): bool
    {
        $decodedKey = $this->decodeKey($key);

        return $this->verifyAuthenticator($message, $mac, $decodedKey);
    }

    public function verifyWithBinaryKey(
        string $message,
        string $mac,
        #[\SensitiveParameter]
        string $key,
    ): bool {
        $this->assertBinaryKey($key);

        return $this->verifyAuthenticator($message, $mac, $key);
    }

    private function assertBinaryKey(#[\SensitiveParameter] string $key): void
    {
        if (strlen($key) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
            throw new InvalidKeyException('MAC key must be 32 bytes.');
        }
    }

    private function decodeKey(#[\SensitiveParameter] string $key): string
    {
        try {
            return BinaryKey::fixedLength($key, false, SODIUM_CRYPTO_AUTH_KEYBYTES, 'MAC key');
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException('MAC key must be 32 bytes.', 0, $e);
        }
    }

    private function verifyAuthenticator(string $message, string $mac, #[\SensitiveParameter] string $key): bool
    {
        try {
            $decoded = Base64Url::decode($mac);
        } catch (\Throwable) {
            return false;
        }

        return strlen($decoded) === SODIUM_CRYPTO_AUTH_BYTES
            && sodium_crypto_auth_verify($decoded, $message, $key);
    }
}
