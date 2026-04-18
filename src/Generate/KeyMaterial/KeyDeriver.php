<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Generate\Support\LengthGuard;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

final class KeyDeriver
{
    /**
     * @param array<string, mixed> $context
     */
    public function deriveFromPassword(string $password, string $salt, int $length = 32, array $context = []): string
    {
        $profile = $this->profileFromContext($context);
        $saltBinary = $this->decodeMaybeBinary($salt, $this->boolFromContext($context, 'salt_is_binary'), 'Salt');
        if (strlen($saltBinary) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new ConfigurationException(sprintf('Salt must be %d bytes.', SODIUM_CRYPTO_PWHASH_SALTBYTES));
        }

        $derived = sodium_crypto_pwhash(
            LengthGuard::atLeastOne($length, 'Derived key length'),
            $password,
            $saltBinary,
            $this->intFromContext($context, 'opslimit', $profile->passwordDerivationOpsLimit()),
            $this->intFromContext($context, 'memlimit', $profile->passwordDerivationMemLimit()),
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );

        return $this->formatOutput($derived, $this->boolFromContext($context, 'as_base64url', true));
    }

    /**
     * @param array<string, mixed> $context
     */
    public function hkdf(string $inputKeyMaterial, int $length = 32, array $context = []): string
    {
        $ikmBinary = $this->decodeMaybeBinary(
            $inputKeyMaterial,
            $this->boolFromContext($context, 'input_key_material_is_binary'),
            'Input key material',
        );
        $saltBinary = '';
        if (array_key_exists('salt', $context)) {
            $salt = $context['salt'];
            if (!is_string($salt)) {
                throw new ConfigurationException('HKDF salt must be a string.');
            }

            $saltBinary = $this->decodeMaybeBinary($salt, $this->boolFromContext($context, 'salt_is_binary'), 'Salt');
        }

        $info = $context['info'] ?? '';
        if (!is_string($info)) {
            throw new ConfigurationException('HKDF info must be a string.');
        }

        $derived = hash_hkdf(
            $this->normalizeHashAlgorithm($context['algorithm'] ?? 'sha256'),
            $ikmBinary,
            LengthGuard::atLeastOne($length, 'Derived key length'),
            $info,
            $saltBinary,
        );

        return $this->formatOutput($derived, $this->boolFromContext($context, 'as_base64url', true));
    }

    /**
     * @param array<string, mixed> $context
     */
    public function subkey(string $rootKey, int $subkeyId, int $length = 32, array $context = []): string
    {
        $rootKeyBinary = $this->decodeMaybeBinary($rootKey, $this->boolFromContext($context, 'root_key_is_binary'), 'Root key');
        if (strlen($rootKeyBinary) !== SODIUM_CRYPTO_KDF_KEYBYTES) {
            throw new ConfigurationException(sprintf('Root key must be %d bytes.', SODIUM_CRYPTO_KDF_KEYBYTES));
        }

        $sodiumContext = $context['context'] ?? 'EPCKDF01';
        if (!is_string($sodiumContext) || strlen($sodiumContext) !== SODIUM_CRYPTO_KDF_CONTEXTBYTES) {
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

        return $this->formatOutput($derived, $this->boolFromContext($context, 'as_base64url', true));
    }

    /**
     * @param array<string, mixed> $context
     */
    private function boolFromContext(array $context, string $key, bool $default = false): bool
    {
        $value = $context[$key] ?? $default;
        if (!is_bool($value)) {
            throw new ConfigurationException(sprintf('Context value "%s" must be boolean.', $key));
        }

        return $value;
    }

    private function decodeMaybeBinary(string $value, bool $isBinary, string $label): string
    {
        $decoded = $isBinary ? $value : Base64Url::decode($value);
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
     * @param array<string, mixed> $context
     */
    private function intFromContext(array $context, string $key, int $default): int
    {
        $value = $context[$key] ?? $default;
        if (!is_int($value) || $value < 1) {
            throw new ConfigurationException(sprintf('Context value "%s" must be a positive integer.', $key));
        }

        return $value;
    }

    /**
     * @return non-falsy-string
     */
    private function normalizeHashAlgorithm(mixed $algorithm): string
    {
        if (!is_string($algorithm) || $algorithm === '' || $algorithm === '0') {
            throw new ConfigurationException('HKDF algorithm must be a non-empty string.');
        }

        return $algorithm;
    }

    /**
     * @param array<string, mixed> $context
     */
    private function profileFromContext(array $context): SecurityProfile
    {
        $profile = $context['profile'] ?? SecurityProfile::MODERN;
        if (!$profile instanceof SecurityProfile) {
            throw new ConfigurationException('Derivation profile must be a SecurityProfile enum.');
        }

        return $profile;
    }
}
