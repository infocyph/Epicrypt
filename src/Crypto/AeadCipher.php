<?php

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidNonceException;
use Infocyph\Epicrypt\Exception\Crypto\UnsupportedCipherException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
use Infocyph\Epicrypt\Internal\VersionedPayload;

final readonly class AeadCipher implements EncryptorInterface, DecryptorInterface
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
        private string $algorithm = SecurityPolicy::DEFAULT_AEAD_ALGORITHM,
    ) {}

    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        $config = $this->config();
        $decodedKey = $this->decodeKey($key, $config['key'], (bool) ($context['key_is_binary'] ?? false), 'Decryption');

        $parsedPayload = VersionedPayload::parse($ciphertext, SecurityPolicy::ENCRYPTED_PAYLOAD_VERSION, 2);
        if ($parsedPayload === null) {
            throw new DecryptionException('Invalid ciphertext format.');
        }
        [, $parts] = $parsedPayload;

        $nonce = Base64Url::decode($parts[0]);
        if (strlen($nonce) !== $config['nonce']) {
            throw new InvalidNonceException(sprintf('Nonce must be %d bytes.', $config['nonce']));
        }

        $aad = (string) ($context['aad'] ?? '');
        $plaintext = call_user_func(
            'sodium_crypto_aead_' . $config['suffix'] . '_decrypt',
            Base64Url::decode($parts[1]),
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
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        $config = $this->config();
        $decodedKey = $this->decodeKey($key, $config['key'], (bool) ($context['key_is_binary'] ?? false), 'Encryption');

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

        return VersionedPayload::encode(
            SecurityPolicy::ENCRYPTED_PAYLOAD_VERSION,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    /**
     * @return array{suffix: string, nonce: int, key: int, requires_hardware?: bool}
     */
    private function config(): array
    {
        if (! isset(self::CONFIG[$this->algorithm])) {
            throw new UnsupportedCipherException('Unsupported AEAD algorithm: ' . $this->algorithm);
        }

        $config = self::CONFIG[$this->algorithm];
        if (($config['requires_hardware'] ?? false) && ! sodium_crypto_aead_aes256gcm_is_available()) {
            throw new UnsupportedCipherException('AES-256-GCM hardware support is not available.');
        }

        return $config;
    }

    private function decodeKey(mixed $key, int $expectedLength, bool $isBinary, string $operation): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException(sprintf('%s key must be a non-empty string.', $operation));
        }

        $decoded = $isBinary ? $key : Base64Url::decode($key);
        if (strlen($decoded) !== $expectedLength) {
            throw new InvalidKeyException(sprintf('%s key must be %d bytes.', $operation, $expectedLength));
        }

        return $decoded;
    }
}
