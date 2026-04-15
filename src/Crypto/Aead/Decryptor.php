<?php

namespace Infocyph\Epicrypt\Crypto\Aead;

use Infocyph\Epicrypt\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\Base64Url;

final readonly class Decryptor implements DecryptorInterface
{
    /**
     * @var array<string, array{suffix: string, nonce: int, key: int, requires_hardware?: bool}>
     */
    private const array CONFIG = [
        'aes-256-gcm' => ['suffix' => 'aes256gcm', 'nonce' => SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES, 'key' => SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES, 'requires_hardware' => true],
        'chacha20-poly1305' => ['suffix' => 'chacha20poly1305', 'nonce' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES, 'key' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES],
        'chacha20-poly1305-ietf' => ['suffix' => 'chacha20poly1305_ietf', 'nonce' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES, 'key' => SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES],
        'xchacha20-poly1305-ietf' => ['suffix' => 'xchacha20poly1305_ietf', 'nonce' => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, 'key' => SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES],
    ];

    public function __construct(
        private string $algorithm = 'xchacha20-poly1305-ietf',
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        $config = $this->config();
        $decodedKey = $this->decodeKey($key, $config['key'], (bool) ($context['key_is_binary'] ?? false));

        [$encodedNonce, $encodedCipher] = $this->splitPayload($ciphertext);
        $nonce = Base64Url::decode($encodedNonce);
        if (strlen($nonce) !== $config['nonce']) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $config['nonce']));
        }

        $aad = (string) ($context['aad'] ?? '');

        $plaintext = call_user_func(
            'sodium_crypto_aead_' . $config['suffix'] . '_decrypt',
            Base64Url::decode($encodedCipher),
            $aad,
            $nonce,
            $decodedKey,
        );

        if (! is_string($plaintext)) {
            throw new DecryptionException('AEAD decryption failed.');
        }

        return $plaintext;
    }

    /**
     * @return array{suffix: string, nonce: int, key: int, requires_hardware?: bool}
     */
    private function config(): array
    {
        if (! isset(self::CONFIG[$this->algorithm])) {
            throw new UnsupportedAlgorithmException('Unsupported AEAD algorithm: ' . $this->algorithm);
        }

        $config = self::CONFIG[$this->algorithm];
        if (($config['requires_hardware'] ?? false) && ! sodium_crypto_aead_aes256gcm_is_available()) {
            throw new UnsupportedAlgorithmException('AES-256-GCM hardware support is not available.');
        }

        return $config;
    }

    private function decodeKey(mixed $key, int $expectedLength, bool $isBinary): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException('Decryption key must be a non-empty string.');
        }

        $decoded = $isBinary ? $key : Base64Url::decode($key);
        if (strlen($decoded) !== $expectedLength) {
            throw new InvalidKeyException(sprintf('Decryption key must be %d bytes.', $expectedLength));
        }

        return $decoded;
    }

    /**
     * @return array{string, string}
     */
    private function splitPayload(string $ciphertext): array
    {
        $parts = explode('.', $ciphertext, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new DecryptionException('Invalid ciphertext format.');
        }

        return [$parts[0], $parts[1]];
    }
}
