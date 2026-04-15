<?php

namespace Infocyph\Epicrypt\DataProtection\OpenSSL;

final class OpenSslFunctions
{
    public static function openssl_cipher_iv_length(string $cipherAlgorithm): int|false
    {
        return openssl_cipher_iv_length($cipherAlgorithm);
    }

    public static function openssl_cipher_key_length(string $cipherAlgorithm): int|false
    {
        return openssl_cipher_key_length($cipherAlgorithm);
    }

    public static function openssl_cms_decrypt(
        string $inputFilename,
        string $outputFilename,
        mixed $certificate,
        mixed $privateKey = null,
        int $encoding = OPENSSL_ENCODING_SMIME,
    ): bool {
        return openssl_cms_decrypt($inputFilename, $outputFilename, $certificate, $privateKey, $encoding);
    }

    public static function openssl_cms_encrypt(
        string $inputFilename,
        string $outputFilename,
        mixed $certificate,
        array $headers,
        int $flags = 0,
        int $encoding = OPENSSL_ENCODING_SMIME,
        int $cipherAlgorithm = OPENSSL_CIPHER_AES_128_CBC,
    ): bool {
        return openssl_cms_encrypt($inputFilename, $outputFilename, $certificate, $headers, $flags, $encoding, $cipherAlgorithm);
    }

    public static function openssl_cms_sign(
        string $inputFilename,
        string $outputFilename,
        mixed $certificate,
        mixed $privateKey,
        ?array $headers = null,
        int $flags = 0,
        int $encoding = OPENSSL_ENCODING_SMIME,
        ?string $untrustedCertificatesFilename = null,
    ): bool {
        return openssl_cms_sign(
            $inputFilename,
            $outputFilename,
            $certificate,
            $privateKey,
            $headers ?? [],
            $flags,
            $encoding,
            $untrustedCertificatesFilename ?? null,
        );
    }

    public static function openssl_cms_verify(
        string $inputFilename,
        int $flags = 0,
        ?string $certificateStore = null,
        array $caInfo = [],
        ?string $untrustedCertificatesFilename = null,
        ?string $content = null,
        ?string $pk7 = null,
        ?string $signatureFilename = null,
        int $encoding = OPENSSL_ENCODING_SMIME,
    ): bool {
        return openssl_cms_verify(
            $inputFilename,
            $flags,
            $certificateStore ?? null,
            $caInfo,
            $untrustedCertificatesFilename ?? null,
            $content ?? null,
            $pk7 ?? null,
            $signatureFilename ?? null,
            $encoding,
        );
    }

    public static function openssl_csr_export(mixed $csr, string &$output, bool $noText = true): bool
    {
        return openssl_csr_export($csr, $output, $noText);
    }

    public static function openssl_csr_export_to_file(mixed $csr, string $outputFilename, bool $noText = true): bool
    {
        return openssl_csr_export_to_file($csr, $outputFilename, $noText);
    }

    public static function openssl_csr_get_public_key(mixed $csr, bool $useShortNames = true): mixed
    {
        return openssl_csr_get_public_key($csr, $useShortNames);
    }

    public static function openssl_csr_get_subject(mixed $csr, bool $useShortNames = true): array|false
    {
        return openssl_csr_get_subject($csr, $useShortNames);
    }

    public static function openssl_csr_new(array $distinguishedNames, mixed &$privateKey, ?array $options = null, ?array $extraAttributes = null): mixed
    {
        return openssl_csr_new($distinguishedNames, $privateKey, $options ?? null, $extraAttributes ?? null);
    }

    public static function openssl_csr_sign(mixed $csr, mixed $caCertificate, mixed $privateKey, int $days, ?array $options = null, int $serial = 0): mixed
    {
        return openssl_csr_sign($csr, $caCertificate, $privateKey, $days, $options ?? null, $serial);
    }

    public static function openssl_decrypt(
        string $data,
        string $cipherAlgorithm,
        string $passphrase,
        int $options = 0,
        string $iv = '',
        ?string $tag = null,
        string $aad = '',
    ): string|false {
        return openssl_decrypt($data, $cipherAlgorithm, $passphrase, $options, $iv, $tag, $aad);
    }

    public static function openssl_dh_compute_key(string $publicKey, mixed $privateKey): string|false
    {
        return openssl_dh_compute_key($publicKey, $privateKey);
    }
    public static function openssl_encrypt(
        string $data,
        string $cipherAlgorithm,
        string $passphrase,
        int $options = 0,
        string $iv = '',
        ?string &$tag = null,
        string $aad = '',
        int $tagLength = 16,
    ): string|false {
        return openssl_encrypt($data, $cipherAlgorithm, $passphrase, $options, $iv, $tag, $aad, $tagLength);
    }

    public static function openssl_get_cipher_methods(bool $aliases = false): array
    {
        return openssl_get_cipher_methods($aliases);
    }

    public static function openssl_open(string $data, string &$output, string $encryptedKey, mixed $privateKey, string $cipherAlgorithm = 'RC4', string $iv = ''): bool
    {
        return openssl_open($data, $output, $encryptedKey, $privateKey, $cipherAlgorithm, $iv);
    }

    public static function openssl_pbkdf2(
        string $password,
        string $salt,
        int $keyLength,
        int $iterations,
        string $digestAlgorithm = 'sha1',
    ): string|false {
        return openssl_pbkdf2($password, $salt, $keyLength, $iterations, $digestAlgorithm);
    }

    public static function openssl_pkcs7_decrypt(
        string $inputFilename,
        string $outputFilename,
        mixed $certificate,
        mixed $privateKey = null,
    ): bool {
        return openssl_pkcs7_decrypt($inputFilename, $outputFilename, $certificate, $privateKey);
    }

    public static function openssl_pkcs7_encrypt(
        string $inputFilename,
        string $outputFilename,
        mixed $certificate,
        array $headers,
        int $flags = 0,
        int $cipherAlgorithm = OPENSSL_CIPHER_RC2_40,
    ): bool {
        return openssl_pkcs7_encrypt($inputFilename, $outputFilename, $certificate, $headers, $flags, $cipherAlgorithm);
    }

    public static function openssl_pkcs7_sign(
        string $inputFilename,
        string $outputFilename,
        mixed $certificate,
        mixed $privateKey,
        array $headers,
        int $flags = PKCS7_DETACHED,
        ?string $untrustedCertificatesFilename = null,
    ): bool {
        return openssl_pkcs7_sign($inputFilename, $outputFilename, $certificate, $privateKey, $headers, $flags, $untrustedCertificatesFilename ?? '');
    }

    public static function openssl_pkcs7_verify(
        string $inputFilename,
        int $flags,
        ?string $signersCertificatesFilename = null,
        array $caInfo = [],
        ?string $untrustedCertificatesFilename = null,
        ?string $content = null,
        ?string $outputFilename = null,
    ): bool|int {
        return openssl_pkcs7_verify(
            $inputFilename,
            $flags,
            $signersCertificatesFilename ?? null,
            $caInfo,
            $untrustedCertificatesFilename ?? null,
            $content ?? null,
            $outputFilename ?? null,
        );
    }

    public static function openssl_pkey_export(mixed $key, string &$output, ?string $passphrase = null, ?array $options = null): bool
    {
        return openssl_pkey_export($key, $output, $passphrase ?? null, $options ?? null);
    }

    public static function openssl_pkey_export_to_file(mixed $key, string $outputFilename, ?string $passphrase = null, ?array $options = null): bool
    {
        return openssl_pkey_export_to_file($key, $outputFilename, $passphrase ?? null, $options ?? null);
    }

    public static function openssl_pkey_get_details(mixed $key): array|false
    {
        return openssl_pkey_get_details($key);
    }

    public static function openssl_pkey_get_private(mixed $privateKey, ?string $passphrase = null): mixed
    {
        return openssl_pkey_get_private($privateKey, $passphrase ?? '');
    }

    public static function openssl_pkey_get_public(mixed $publicKey): mixed
    {
        return openssl_pkey_get_public($publicKey);
    }

    public static function openssl_pkey_new(?array $options = null): mixed
    {
        return openssl_pkey_new($options);
    }

    public static function openssl_private_decrypt(string $data, string &$decryptedData, mixed $privateKey, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return openssl_private_decrypt($data, $decryptedData, $privateKey, $padding);
    }

    public static function openssl_private_encrypt(string $data, string &$encryptedData, mixed $privateKey, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return openssl_private_encrypt($data, $encryptedData, $privateKey, $padding);
    }

    public static function openssl_public_decrypt(string $data, string &$decryptedData, mixed $publicKey, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return openssl_public_decrypt($data, $decryptedData, $publicKey, $padding);
    }

    public static function openssl_public_encrypt(string $data, string &$encryptedData, mixed $publicKey, int $padding = OPENSSL_PKCS1_PADDING): bool
    {
        return openssl_public_encrypt($data, $encryptedData, $publicKey, $padding);
    }

    public static function openssl_random_pseudo_bytes(int $length, ?bool &$strongResult = null): string
    {
        return openssl_random_pseudo_bytes($length, $strongResult);
    }

    public static function openssl_seal(
        string $data,
        string &$sealedData,
        array &$encryptedKeys,
        array $publicKey,
        string $cipherAlgorithm = 'RC4',
        string &$iv = '',
    ): int|false {
        return openssl_seal($data, $sealedData, $encryptedKeys, $publicKey, $cipherAlgorithm, $iv);
    }

    public static function openssl_sign(string $data, string &$signature, mixed $privateKey, string|int $algorithm = OPENSSL_ALGO_SHA1): bool
    {
        return openssl_sign($data, $signature, $privateKey, $algorithm);
    }

    public static function openssl_verify(string $data, string $signature, mixed $publicKey, string|int $algorithm = OPENSSL_ALGO_SHA1): int|false
    {
        return openssl_verify($data, $signature, $publicKey, $algorithm);
    }

    public static function openssl_x509_checkpurpose(
        mixed $certificate,
        int $purpose,
        array $caInfo = [],
        ?string $untrustedFile = null,
    ): int|false {
        return openssl_x509_checkpurpose($certificate, $purpose, $caInfo, $untrustedFile);
    }

    public static function openssl_x509_export(mixed $certificate, string &$output, bool $noText = true): bool
    {
        return openssl_x509_export($certificate, $output, $noText);
    }

    public static function openssl_x509_export_to_file(mixed $certificate, string $outputFilename, bool $noText = true): bool
    {
        return openssl_x509_export_to_file($certificate, $outputFilename, $noText);
    }

    public static function openssl_x509_fingerprint(mixed $certificate, string $digestAlgorithm = 'sha1', bool $binary = false): string|false
    {
        return openssl_x509_fingerprint($certificate, $digestAlgorithm, $binary);
    }

    public static function openssl_x509_parse(mixed $certificate, bool $shortNames = true): array|false
    {
        return openssl_x509_parse($certificate, $shortNames);
    }

    public static function openssl_x509_read(mixed $certificate): mixed
    {
        return openssl_x509_read($certificate);
    }

    public static function openssl_x509_verify(mixed $certificate, mixed $publicKey): int
    {
        return openssl_x509_verify($certificate, $publicKey);
    }
}
