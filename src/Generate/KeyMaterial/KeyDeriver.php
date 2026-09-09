<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Generate\KeyMaterial\Enum\HkdfAlgorithm;
use Infocyph\Epicrypt\Internal\Base64Url;

final class KeyDeriver
{
    private const int MAX_PASSWORD_DERIVATION_OPSLIMIT = 10;

    private const int MAX_PASSWORD_DERIVED_KEY_BYTES = 64;

    private const int MAX_PURPOSE_CONTEXT_BYTES = 512;

    private const int MAX_PURPOSE_KEY_BYTES = 64;

    private const int MAX_PURPOSE_LABEL_BYTES = 128;

    private const int MIN_PASSWORD_DERIVATION_MEMORY_BYTES = 8192;

    private const int MIN_PASSWORD_DERIVED_KEY_BYTES = 16;

    private const int MIN_PURPOSE_KEY_BYTES = 16;

    private const int MIN_PURPOSE_MASTER_KEY_BYTES = 32;

    public function deriveBinaryFromPassword(
        #[\SensitiveParameter]
        string $password,
        string $salt,
        int $length = 32,
        int $opslimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        int $memlimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
    ): string {
        return $this->derivePasswordBinary($password, $salt, $length, $opslimit, $memlimit);
    }

    public function deriveFromPassword(
        #[\SensitiveParameter]
        string $password,
        string $salt,
        int $length = 32,
        int $opslimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
        int $memlimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
    ): string {
        return Base64Url::encode($this->derivePasswordBinary(
            $password,
            Base64Url::decode($salt),
            $length,
            $opslimit,
            $memlimit,
        ));
    }

    public function derivePurposeKey(
        #[\SensitiveParameter]
        string $masterKey,
        string $label,
        string $context = '',
        int $length = 32,
        ?string $salt = null,
    ): string {
        return Base64Url::encode($this->derivePurposeKeyBinary(
            Base64Url::decode($masterKey),
            $label,
            $context,
            $length,
            $salt === null ? '' : Base64Url::decode($salt),
        ));
    }

    public function derivePurposeKeyBinary(
        #[\SensitiveParameter]
        string $masterKey,
        string $label,
        string $context = '',
        int $length = 32,
        string $salt = '',
    ): string {
        if (strlen($masterKey) < self::MIN_PURPOSE_MASTER_KEY_BYTES) {
            throw new ConfigurationException(sprintf(
                'Purpose master key must contain at least %d raw bytes.',
                self::MIN_PURPOSE_MASTER_KEY_BYTES,
            ));
        }
        $this->assertPurposePart($label, self::MAX_PURPOSE_LABEL_BYTES, 'Purpose key label', allowEmpty: false);
        $this->assertPurposePart($context, self::MAX_PURPOSE_CONTEXT_BYTES, 'Purpose key context', allowEmpty: true);
        $this->assertOutputLength($length, self::MIN_PURPOSE_KEY_BYTES, self::MAX_PURPOSE_KEY_BYTES, 'Purpose-derived key length');

        $info = 'epicrypt:purpose-key:v1'
            . pack('N', strlen($label)) . $label
            . pack('N', strlen($context)) . $context;

        return $this->deriveHkdf($masterKey, $length, HkdfAlgorithm::SHA256, $info, $salt);
    }

    public function hkdf(
        #[\SensitiveParameter]
        string $inputKeyMaterial,
        int $length = 32,
        HkdfAlgorithm $algorithm = HkdfAlgorithm::SHA256,
        string $info = '',
        ?string $salt = null,
    ): string {
        return Base64Url::encode($this->deriveHkdf(
            Base64Url::decode($inputKeyMaterial),
            $length,
            $algorithm,
            $info,
            $salt === null ? '' : Base64Url::decode($salt),
        ));
    }

    public function hkdfBinary(
        #[\SensitiveParameter]
        string $inputKeyMaterial,
        int $length = 32,
        HkdfAlgorithm $algorithm = HkdfAlgorithm::SHA256,
        string $info = '',
        string $salt = '',
    ): string {
        return $this->deriveHkdf($inputKeyMaterial, $length, $algorithm, $info, $salt);
    }

    public function subkey(
        #[\SensitiveParameter]
        string $rootKey,
        int $subkeyId,
        string $context,
        int $length = 32,
    ): string {
        return Base64Url::encode($this->deriveSubkey(Base64Url::decode($rootKey), $subkeyId, $context, $length));
    }

    public function subkeyBinary(
        #[\SensitiveParameter]
        string $rootKey,
        int $subkeyId,
        string $context,
        int $length = 32,
    ): string {
        return $this->deriveSubkey($rootKey, $subkeyId, $context, $length);
    }

    private function assertOutputLength(int $length, int $minimum, int $maximum, string $label): void
    {
        if ($length < $minimum || $length > $maximum) {
            throw new ConfigurationException(sprintf('%s must be between %d and %d bytes.', $label, $minimum, $maximum));
        }
    }

    private function assertPurposePart(string $value, int $maximum, string $label, bool $allowEmpty): void
    {
        $length = strlen($value);
        if ((!$allowEmpty && $length === 0) || $length > $maximum || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            $minimum = $allowEmpty ? 0 : 1;

            throw new ConfigurationException(sprintf(
                '%s must be %d..%d bytes and contain no control characters.',
                $label,
                $minimum,
                $maximum,
            ));
        }
    }

    private function deriveHkdf(
        #[\SensitiveParameter]
        string $inputKeyMaterial,
        int $length,
        HkdfAlgorithm $algorithm,
        string $info,
        string $salt,
    ): string {
        if ($inputKeyMaterial === '') {
            throw new ConfigurationException('HKDF input key material must not be empty.');
        }
        $maximum = 255 * strlen(hash($algorithm->value, '', true));
        if ($length < 1 || $length > $maximum) {
            throw new ConfigurationException(sprintf('HKDF output length must be between 1 and %d bytes.', $maximum));
        }

        return hash_hkdf($algorithm->value, $inputKeyMaterial, $length, $info, $salt);
    }

    private function derivePasswordBinary(
        #[\SensitiveParameter]
        string $password,
        string $salt,
        int $length,
        int $opslimit,
        int $memlimit,
    ): string {
        if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new ConfigurationException(sprintf('Salt must be exactly %d bytes.', SODIUM_CRYPTO_PWHASH_SALTBYTES));
        }
        $this->assertOutputLength($length, self::MIN_PASSWORD_DERIVED_KEY_BYTES, self::MAX_PASSWORD_DERIVED_KEY_BYTES, 'Password-derived key length');
        if ($opslimit < 1 || $opslimit > self::MAX_PASSWORD_DERIVATION_OPSLIMIT) {
            throw new ConfigurationException('Password derivation operation limit is outside the Sodium range.');
        }
        if ($memlimit < self::MIN_PASSWORD_DERIVATION_MEMORY_BYTES || $memlimit > SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE) {
            throw new ConfigurationException('Password derivation memory limit is outside the Sodium range.');
        }

        return sodium_crypto_pwhash(
            $length,
            $password,
            $salt,
            $opslimit,
            $memlimit,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13,
        );
    }

    private function deriveSubkey(
        #[\SensitiveParameter]
        string $rootKey,
        int $subkeyId,
        string $context,
        int $length,
    ): string {
        if (strlen($rootKey) !== SODIUM_CRYPTO_KDF_KEYBYTES) {
            throw new ConfigurationException(sprintf('Root key must be exactly %d bytes.', SODIUM_CRYPTO_KDF_KEYBYTES));
        }
        if (strlen($context) !== SODIUM_CRYPTO_KDF_CONTEXTBYTES) {
            throw new ConfigurationException(sprintf('Subkey context must be exactly %d bytes.', SODIUM_CRYPTO_KDF_CONTEXTBYTES));
        }
        if ($subkeyId < 0) {
            throw new ConfigurationException('Subkey id must be a non-negative integer.');
        }
        $this->assertOutputLength($length, SODIUM_CRYPTO_KDF_BYTES_MIN, SODIUM_CRYPTO_KDF_BYTES_MAX, 'Derived subkey length');

        return sodium_crypto_kdf_derive_from_key($length, $subkeyId, $context, $rootKey);
    }
}
