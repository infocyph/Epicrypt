<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Generate\Support\LengthGuard;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;
use Infocyph\Epicrypt\Internal\HashAlgorithm;

final class KeyDeriver
{
    public function deriveFromPassword(
        string $password,
        string $salt,
        int $length = 32,
        KeyDerivationContext $context = new KeyDerivationContext(),
    ): string {
        $derivationContext = $context;
        $saltBinary = $this->decodeMaybeBinary($salt, $derivationContext->saltIsBinary, 'Salt');
        if (strlen($saltBinary) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new ConfigurationException(sprintf('Salt must be %d bytes.', SODIUM_CRYPTO_PWHASH_SALTBYTES));
        }

        $derived = sodium_crypto_pwhash(
            LengthGuard::atLeastOne($length, 'Derived key length'),
            $password,
            $saltBinary,
            $derivationContext->opslimit ?? SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            $derivationContext->memlimit ?? SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );

        return $this->formatOutput($derived, $derivationContext->asBase64Url);
    }

    public function hkdf(
        string $inputKeyMaterial,
        int $length = 32,
        KeyDerivationContext $context = new KeyDerivationContext(),
    ): string {
        $derivationContext = $context;
        $ikmBinary = $this->decodeMaybeBinary(
            $inputKeyMaterial,
            $derivationContext->inputKeyMaterialIsBinary,
            'Input key material',
        );
        $saltBinary = '';
        if ($derivationContext->salt !== null) {
            $saltBinary = $this->decodeMaybeBinary($derivationContext->salt, $derivationContext->saltIsBinary, 'Salt');
        }

        $derived = hash_hkdf(
            $this->normalizeHashAlgorithm($derivationContext->algorithm),
            $ikmBinary,
            LengthGuard::atLeastOne($length, 'Derived key length'),
            $derivationContext->info,
            $saltBinary,
        );

        return $this->formatOutput($derived, $derivationContext->asBase64Url);
    }

    public function subkey(
        string $rootKey,
        int $subkeyId,
        int $length = 32,
        KeyDerivationContext $context = new KeyDerivationContext(),
    ): string {
        $derivationContext = $context;
        $rootKeyBinary = $this->decodeMaybeBinary($rootKey, $derivationContext->rootKeyIsBinary, 'Root key');
        if (strlen($rootKeyBinary) !== SODIUM_CRYPTO_KDF_KEYBYTES) {
            throw new ConfigurationException(sprintf('Root key must be %d bytes.', SODIUM_CRYPTO_KDF_KEYBYTES));
        }

        $sodiumContext = $derivationContext->sodiumContext;
        if (strlen($sodiumContext) !== SODIUM_CRYPTO_KDF_CONTEXTBYTES) {
            throw new ConfigurationException(sprintf('Subkey context must be exactly %d bytes.', SODIUM_CRYPTO_KDF_CONTEXTBYTES));
        }

        $requestedLength = LengthGuard::atLeastOne($length, 'Derived key length');
        if ($requestedLength < SODIUM_CRYPTO_KDF_BYTES_MIN || $requestedLength > SODIUM_CRYPTO_KDF_BYTES_MAX) {
            throw new ConfigurationException(sprintf(
                'Derived key length must be between %d and %d bytes.',
                SODIUM_CRYPTO_KDF_BYTES_MIN,
                SODIUM_CRYPTO_KDF_BYTES_MAX,
            ));
        }

        if ($subkeyId < 0) {
            throw new ConfigurationException('Subkey id must be a non-negative integer.');
        }

        $derived = sodium_crypto_kdf_derive_from_key($requestedLength, $subkeyId, $sodiumContext, $rootKeyBinary);

        return $this->formatOutput($derived, $derivationContext->asBase64Url);
    }

    private function decodeMaybeBinary(string $value, bool $isBinary, string $label): string
    {
        try {
            $decoded = BinaryKey::decodeBase64UrlOrBinary($value, $isBinary, $label);
        } catch (\Throwable $e) {
            throw new ConfigurationException(sprintf('%s must be a non-empty string.', $label), 0, $e);
        }

        if ($decoded === '') {
            throw new ConfigurationException(sprintf('%s must not be empty.', $label));
        }

        return $decoded;
    }

    private function formatOutput(string $derived, bool $asBase64Url): string
    {
        return $asBase64Url ? Base64Url::encode($derived) : $derived;
    }

    /**
     * @return non-falsy-string
     */
    private function normalizeHashAlgorithm(mixed $algorithm): string
    {
        if (!is_string($algorithm) || $algorithm === '' || $algorithm === '0') {
            throw new ConfigurationException('HKDF algorithm must be a non-empty string.');
        }

        try {
            HashAlgorithm::assertSupported($algorithm);
        } catch (\InvalidArgumentException $e) {
            throw new ConfigurationException($e->getMessage(), 0, $e);
        }

        return $algorithm;
    }
}
