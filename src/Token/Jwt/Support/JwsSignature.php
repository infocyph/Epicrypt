<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\EcdsaSignatureConverter;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use OpenSSLAsymmetricKey;
use phpseclib4\Crypt\PublicKeyLoader;
use phpseclib4\Crypt\RSA;
use phpseclib4\Crypt\RSA\PrivateKey as RsaPrivateKey;
use phpseclib4\Crypt\RSA\PublicKey as RsaPublicKey;

/** @internal */
final readonly class JwsSignature
{
    public function __construct(
        #[\SensitiveParameter]
        private string $key,
        private SymmetricJwtAlgorithm|AsymmetricJwtAlgorithm $algorithm,
        private bool $signing,
        #[\SensitiveParameter]
        private ?string $passphrase = null,
    ) {
        $this->validateKey();
    }

    public function sign(#[\SensitiveParameter] string $input): string
    {
        if (!$this->signing) {
            throw new ConfigurationException('JWS signature backend is not configured for signing.');
        }
        if ($this->algorithm instanceof SymmetricJwtAlgorithm) {
            return hash_hmac($this->algorithm->hmacAlgorithm(), $input, $this->key, true);
        }
        if ($this->algorithm->isEdDsa()) {
            return sodium_crypto_sign_detached($input, $this->nonEmptyKey());
        }
        if ($this->algorithm->isRsaPss()) {
            return $this->rsaPssPrivateKey()->sign($input);
        }
        $key = $this->opensslKey();
        if (!openssl_sign($input, $signature, $key, $this->algorithm->opensslAlgorithm()) || !is_string($signature)) {
            throw new ConfigurationException('JWS signing failed.');
        }
        $length = $this->algorithm->ecdsaSignatureLength();

        return $length === null ? $signature : new EcdsaSignatureConverter()->fromAsn1($signature, $length);
    }

    public function verify(#[\SensitiveParameter] string $input, string $signature): bool
    {
        if ($this->signing) {
            throw new ConfigurationException('JWS signature backend is not configured for verification.');
        }
        if ($this->algorithm instanceof SymmetricJwtAlgorithm) {
            return hash_equals(hash_hmac($this->algorithm->hmacAlgorithm(), $input, $this->key, true), $signature);
        }
        if ($this->algorithm->isEdDsa()) {
            return strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
                && sodium_crypto_sign_verify_detached($signature, $input, $this->nonEmptyKey());
        }
        if ($this->algorithm->isRsaPss()) {
            return $this->rsaPssPublicKey()->verify($input, $signature);
        }
        $length = $this->algorithm->ecdsaSignatureLength();
        if ($length !== null) {
            $signature = new EcdsaSignatureConverter()->toAsn1($signature, $length);
        }

        return openssl_verify($input, $signature, $this->opensslKey(), $this->algorithm->opensslAlgorithm()) === 1;
    }

    private function configuredPss(
        #[\SensitiveParameter]
        RsaPrivateKey|RsaPublicKey $key,
    ): RsaPrivateKey|RsaPublicKey {
        if (!$this->algorithm instanceof AsymmetricJwtAlgorithm) {
            throw new ConfigurationException('RSA-PSS requires an asymmetric algorithm.');
        }
        $hash = $this->algorithm->hashAlgorithm();

        return $key
            ->withPadding(RSA::SIGNATURE_PSS)
            ->withHash($hash)
            ->withMGFHash($hash)
            ->withSaltLength(strlen(hash($hash, '', true)));
    }

    /** @return non-empty-string */
    private function nonEmptyKey(): string
    {
        return $this->key !== '' ? $this->key : throw new ConfigurationException('JWS key must not be empty.');
    }

    private function opensslKey(): OpenSSLAsymmetricKey
    {
        $key = $this->signing
            ? openssl_pkey_get_private($this->key, $this->passphrase ?? '')
            : openssl_pkey_get_public($this->key);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new ConfigurationException('Unable to load JWS key material.');
        }
        $details = openssl_pkey_get_details($key);
        if (!is_array($details)) {
            throw new ConfigurationException('Unable to inspect JWS key material.');
        }
        if (str_starts_with($this->algorithm->value, 'RS') || str_starts_with($this->algorithm->value, 'PS')) {
            if (($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || !is_int($details['bits'] ?? null) || $details['bits'] < 2048) {
                throw new ConfigurationException('RSA JWS keys must contain at least 2048 bits.');
            }
        } elseif (($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC) {
            throw new ConfigurationException('ECDSA JWS requires an EC key.');
        }

        return $key;
    }

    private function rsaPssPrivateKey(): RsaPrivateKey
    {
        try {
            $loaded = PublicKeyLoader::loadPrivateKey($this->key, $this->passphrase);
        } catch (\Throwable $exception) {
            throw new ConfigurationException('Unable to load RSA-PSS private key material.', 0, $exception);
        }
        if (!$loaded instanceof RsaPrivateKey) {
            throw new ConfigurationException('RSA-PSS signing requires an RSA private key.');
        }
        $configured = $this->configuredPss($loaded);

        return $configured instanceof RsaPrivateKey
            ? $configured
            : throw new ConfigurationException('Invalid RSA-PSS private key.');
    }

    private function rsaPssPublicKey(): RsaPublicKey
    {
        try {
            $loaded = PublicKeyLoader::loadPublicKey($this->key);
        } catch (\Throwable $exception) {
            throw new ConfigurationException('Unable to load RSA-PSS public key material.', 0, $exception);
        }
        if (!$loaded instanceof RsaPublicKey) {
            throw new ConfigurationException('RSA-PSS verification requires an RSA public key.');
        }
        $configured = $this->configuredPss($loaded);

        return $configured instanceof RsaPublicKey
            ? $configured
            : throw new ConfigurationException('Invalid RSA-PSS public key.');
    }

    private function validateKey(): void
    {
        if ($this->algorithm instanceof SymmetricJwtAlgorithm) {
            $minimum = match ($this->algorithm) {
                SymmetricJwtAlgorithm::HS256 => 32,
                SymmetricJwtAlgorithm::HS384 => 48,
                SymmetricJwtAlgorithm::HS512 => 64,
            };
            if (strlen($this->key) < $minimum) {
                throw new ConfigurationException(sprintf('%s JWS keys must contain at least %d raw bytes.', $this->algorithm->value, $minimum));
            }

            return;
        }
        if ($this->algorithm->isEdDsa()) {
            $expected = $this->signing ? SODIUM_CRYPTO_SIGN_SECRETKEYBYTES : SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;
            if (strlen($this->key) !== $expected) {
                throw new ConfigurationException(sprintf('EdDSA JWS keys must contain exactly %d raw bytes.', $expected));
            }

            return;
        }
        $this->opensslKey();
        if ($this->algorithm->isRsaPss()) {
            $this->signing ? $this->rsaPssPrivateKey() : $this->rsaPssPublicKey();
        }
    }
}
