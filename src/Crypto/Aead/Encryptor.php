<?php

namespace Infocyph\Epicrypt\Crypto\Aead;

use Infocyph\Epicrypt\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\Base64Url;

final readonly class Encryptor implements EncryptorInterface
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
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        $config = $this->config();
        $decodedKey = $this->decodeKey($key, $config['key'], (bool) ($context['key_is_binary'] ?? false));

        if (array_key_exists('nonce', $context)) {
            $nonce = $context['nonce'];
            if (! is_string($nonce) || $nonce === '') {
                throw new InvalidNonceException('Nonce must be a non-empty string.');
            }

            if (! (bool) ($context['nonce_is_binary'] ?? false)) {
                $nonce = Base64Url::decode($nonce);
            }
        } else {
            $nonce = random_bytes($config['nonce']);
        }

        if (strlen($nonce) !== $config['nonce']) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $config['nonce']));
        }

        $aad = (string) ($context['aad'] ?? '');

        $ciphertext = call_user_func(
            'sodium_crypto_aead_' . $config['suffix'] . '_encrypt',
            $plaintext,
            $aad,
            $nonce,
            $decodedKey,
        );

        if (! is_string($ciphertext)) {
            throw new EncryptionException('AEAD encryption failed.');
        }

        return Base64Url::encode($nonce) . '.' . Base64Url::encode($ciphertext);
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

    /**
     * @param array{suffix: string, nonce: int, key: int, requires_hardware?: bool} $config
     */
    private function decodeKey(mixed $key, int $expectedLength, bool $isBinary): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException('Encryption key must be a non-empty string.');
        }

        $decoded = $isBinary ? $key : Base64Url::decode($key);
        if (strlen($decoded) !== $expectedLength) {
            throw new InvalidKeyException(sprintf('Encryption key must be %d bytes.', $expectedLength));
        }

        return $decoded;
    }
}
