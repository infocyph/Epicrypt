<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

/** @internal JOSE key-management and Concat-KDF boundary. */
final class JweKeyManager
{
    /** @param array<string, mixed> $header */
    public function unwrap(
        JweKeyManagementAlgorithm $algorithm,
        #[\SensitiveParameter]
        string $key,
        string $encryptedKey,
        array $header,
    ): string {
        return match ($algorithm) {
            JweKeyManagementAlgorithm::DIRECT => $this->directUnwrap($key, $encryptedKey),
            JweKeyManagementAlgorithm::A256KW => new AesKeyWrap()->unwrap($this->symmetricKey($key), $encryptedKey),
            JweKeyManagementAlgorithm::A256GCMKW => $this->aesGcmUnwrap($key, $encryptedKey, $header),
            JweKeyManagementAlgorithm::RSA_OAEP_256 => $this->rsaUnwrap($key, $encryptedKey),
            JweKeyManagementAlgorithm::ECDH_ES,
            JweKeyManagementAlgorithm::ECDH_ES_A256KW => $this->ecdhUnwrap($algorithm, $key, $encryptedKey, $header),
        };
    }

    /**
     * @param array<string, mixed> $header
     * @return array{cek: string, encryptedKey: string, header: array<string, mixed>}
     */
    public function wrap(
        JweKeyManagementAlgorithm $algorithm,
        #[\SensitiveParameter]
        string $key,
        array $header,
        ?string $sharedCek = null,
    ): array {
        $cek = $sharedCek ?? random_bytes(32);

        return match ($algorithm) {
            JweKeyManagementAlgorithm::DIRECT => $this->direct($key, $header),
            JweKeyManagementAlgorithm::A256KW => $this->aesKw($key, $cek, $header),
            JweKeyManagementAlgorithm::A256GCMKW => $this->aesGcmKw($key, $cek, $header),
            JweKeyManagementAlgorithm::RSA_OAEP_256 => $this->rsaWrap($key, $cek, $header),
            JweKeyManagementAlgorithm::ECDH_ES,
            JweKeyManagementAlgorithm::ECDH_ES_A256KW => $this->ecdhWrap($algorithm, $key, $cek, $header),
        };
    }

    /**
     * @param array<string, mixed> $header
     * @return array{cek: string, encryptedKey: string, header: array<string, mixed>}
     */
    private function aesGcmKw(string $key, string $cek, array $header): array
    {
        $iv = random_bytes(12);
        $tag = '';
        $wrapped = openssl_encrypt($cek, 'aes-256-gcm', $this->symmetricKey($key), OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if (!is_string($wrapped) || strlen($tag) !== 16) {
            throw new InvalidTokenException('JWE A256GCMKW encryption failed.');
        }
        $header['iv'] = Base64Url::encode($iv);
        $header['tag'] = Base64Url::encode($tag);

        return ['cek' => $cek, 'encryptedKey' => $wrapped, 'header' => $header];
    }

    /** @param array<string, mixed> $header */
    private function aesGcmUnwrap(string $key, string $encryptedKey, array $header): string
    {
        $iv = $this->headerBytes($header, 'iv', 12);
        $tag = $this->headerBytes($header, 'tag', 16);
        $cek = openssl_decrypt($encryptedKey, 'aes-256-gcm', $this->symmetricKey($key), OPENSSL_RAW_DATA, $iv, $tag);
        if (!is_string($cek) || strlen($cek) !== 32) {
            throw new InvalidTokenException('JWE A256GCMKW authentication failed.');
        }

        return $cek;
    }

    /**
     * @param array<string, mixed> $header
     * @return array{cek: string, encryptedKey: string, header: array<string, mixed>}
     */
    private function aesKw(string $key, string $cek, array $header): array
    {
        return ['cek' => $cek, 'encryptedKey' => new AesKeyWrap()->wrap($this->symmetricKey($key), $cek), 'header' => $header];
    }

    private function concatKdf(string $secret, string $algorithm, string $apu, string $apv): string
    {
        $lengthPrefixed = static fn(string $value): string => pack('N', strlen($value)) . $value;
        $otherInfo = $lengthPrefixed($algorithm) . $lengthPrefixed($apu) . $lengthPrefixed($apv) . pack('N', 256);

        return hash('sha256', pack('N', 1) . $secret . $otherInfo, true);
    }

    /**
     * @param array<string, mixed> $header
     * @return array{cek: string, encryptedKey: string, header: array<string, mixed>}
     */
    private function direct(string $key, array $header): array
    {
        return ['cek' => $this->symmetricKey($key), 'encryptedKey' => '', 'header' => $header];
    }

    private function directUnwrap(string $key, string $encryptedKey): string
    {
        if ($encryptedKey !== '') {
            throw new InvalidTokenException('Direct JWE must have an empty encrypted-key segment.');
        }

        return $this->symmetricKey($key);
    }

    /** @param array<string, mixed> $header */
    private function ecdhUnwrap(JweKeyManagementAlgorithm $algorithm, string $privateKey, string $encryptedKey, array $header): string
    {
        if (strlen($privateKey) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES || !is_array($header['epk'] ?? null)) {
            throw new InvalidTokenException('ECDH-ES requires a private X25519 key and protected epk.');
        }
        $epk = [];
        foreach ($header['epk'] as $name => $value) {
            if (is_string($name)) {
                $epk[$name] = $value;
            }
        }
        $public = new Jwks()->importOkpPublicKey($epk, $algorithm->value, 'X25519');
        $secret = sodium_crypto_scalarmult($privateKey, $public);
        [$apu, $apv] = $this->partyInfo($header);
        $derived = $this->concatKdf($secret, $algorithm === JweKeyManagementAlgorithm::ECDH_ES ? 'A256GCM' : $algorithm->value, $apu, $apv);
        sodium_memzero($secret);
        if ($algorithm === JweKeyManagementAlgorithm::ECDH_ES) {
            if ($encryptedKey !== '') {
                throw new InvalidTokenException('Direct ECDH-ES must have an empty encrypted key.');
            }

            return $derived;
        }

        return new AesKeyWrap()->unwrap($derived, $encryptedKey);
    }

    /**
     * @param array<string, mixed> $header
     * @return array{cek: string, encryptedKey: string, header: array<string, mixed>}
     */
    private function ecdhWrap(JweKeyManagementAlgorithm $algorithm, string $publicKey, string $cek, array $header): array
    {
        if (strlen($publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidTokenException('ECDH-ES requires a 32-byte X25519 public key.');
        }
        $ephemeralSecret = random_bytes(SODIUM_CRYPTO_BOX_SECRETKEYBYTES);
        $ephemeralPublic = sodium_crypto_scalarmult_base($ephemeralSecret);
        $secret = sodium_crypto_scalarmult($ephemeralSecret, $publicKey);
        sodium_memzero($ephemeralSecret);
        $header['epk'] = new Jwks()->exportOkpPublicKey($ephemeralPublic, 'ephemeral', $algorithm->value, 'X25519');
        unset($header['epk']['kid'], $header['epk']['alg'], $header['epk']['use'], $header['epk']['key_ops']);
        [$apu, $apv] = $this->partyInfo($header);
        $derived = $this->concatKdf($secret, $algorithm === JweKeyManagementAlgorithm::ECDH_ES ? 'A256GCM' : $algorithm->value, $apu, $apv);
        sodium_memzero($secret);
        if ($algorithm === JweKeyManagementAlgorithm::ECDH_ES) {
            return ['cek' => $derived, 'encryptedKey' => '', 'header' => $header];
        }

        return ['cek' => $cek, 'encryptedKey' => new AesKeyWrap()->wrap($derived, $cek), 'header' => $header];
    }

    /** @param array<string, mixed> $header */
    private function headerBytes(array $header, string $name, int $length): string
    {
        try {
            $value = is_string($header[$name] ?? null) ? Base64Url::decode($header[$name]) : '';
        } catch (\Throwable $exception) {
            throw new InvalidTokenException(sprintf('JWE %s header is invalid.', $name), 0, $exception);
        }
        if (strlen($value) !== $length) {
            throw new InvalidTokenException(sprintf('JWE %s header has an invalid size.', $name));
        }

        return $value;
    }

    /** @param array<string, mixed> $header */
    private function optionalHeaderBytes(array $header, string $name): string
    {
        if (!isset($header[$name])) {
            return '';
        }
        if (!is_string($header[$name])) {
            throw new InvalidTokenException(sprintf('JWE %s must be Base64URL text.', $name));
        }

        return Base64Url::decode($header[$name]);
    }

    /**
     * @param array<string, mixed> $header
     * @return array{string, string}
     */
    private function partyInfo(array $header): array
    {
        return [$this->optionalHeaderBytes($header, 'apu'), $this->optionalHeaderBytes($header, 'apv')];
    }

    private function rsaUnwrap(string $privateKey, string $encryptedKey): string
    {
        try {
            $resource = openssl_pkey_get_private($privateKey, '');
            $normalized = '';
            if ($resource === false || !openssl_pkey_export($resource, $normalized) || !is_string($normalized)) {
                throw new \RuntimeException('RSA private key normalization failed.');
            }
            $rsa = PublicKeyLoader::loadPrivateKey($normalized);
            if (!$rsa instanceof \phpseclib3\Crypt\RSA\PrivateKey) {
                throw new \RuntimeException('RSA private key required.');
            }
            $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);
            if (!$rsa instanceof \phpseclib3\Crypt\RSA\PrivateKey) {
                throw new \RuntimeException('RSA padding configuration failed.');
            }
            $rsa = $rsa->withHash('sha256');
            if (!$rsa instanceof \phpseclib3\Crypt\RSA\PrivateKey) {
                throw new \RuntimeException('RSA hash configuration failed.');
            }
            $rsa = $rsa->withMGFHash('sha256');
            if (!$rsa instanceof \phpseclib3\Crypt\RSA\PrivateKey) {
                throw new \RuntimeException('RSA MGF configuration failed.');
            }
            $cek = $rsa->decrypt($encryptedKey);
        } catch (\Throwable $exception) {
            throw new InvalidTokenException('JWE RSA-OAEP-256 decryption failed.', 0, $exception);
        }
        if (!is_string($cek) || strlen($cek) !== 32) {
            throw new InvalidTokenException('JWE RSA-OAEP-256 returned an invalid content key.');
        }

        return $cek;
    }

    /**
     * @param array<string, mixed> $header
     * @return array{cek: string, encryptedKey: string, header: array<string, mixed>}
     */
    private function rsaWrap(string $publicKey, string $cek, array $header): array
    {
        try {
            $rsa = PublicKeyLoader::loadPublicKey($publicKey);
            if (!$rsa instanceof \phpseclib3\Crypt\RSA\PublicKey) {
                throw new \RuntimeException('RSA public key required.');
            }
            $rsa = $rsa->withPadding(RSA::ENCRYPTION_OAEP);
            if (!$rsa instanceof \phpseclib3\Crypt\RSA\PublicKey) {
                throw new \RuntimeException('RSA padding configuration failed.');
            }
            $rsa = $rsa->withHash('sha256');
            if (!$rsa instanceof \phpseclib3\Crypt\RSA\PublicKey) {
                throw new \RuntimeException('RSA hash configuration failed.');
            }
            $rsa = $rsa->withMGFHash('sha256');
            if (!$rsa instanceof \phpseclib3\Crypt\RSA\PublicKey) {
                throw new \RuntimeException('RSA MGF configuration failed.');
            }
            $encrypted = $rsa->encrypt($cek);
            if (!is_string($encrypted)) {
                throw new \RuntimeException('RSA encryption returned invalid output.');
            }
        } catch (\Throwable $exception) {
            throw new InvalidTokenException('JWE RSA-OAEP-256 encryption failed.', 0, $exception);
        }

        return ['cek' => $cek, 'encryptedKey' => $encrypted, 'header' => $header];
    }

    private function symmetricKey(string $key): string
    {
        if (strlen($key) !== 32) {
            throw new InvalidTokenException('JWE symmetric key-management requires exactly 256 bits.');
        }

        return $key;
    }
}
