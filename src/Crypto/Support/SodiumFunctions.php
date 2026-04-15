<?php

namespace Infocyph\Epicrypt\Crypto\Support;

final class SodiumFunctions
{
    public static function sodium_base642bin(string $string, int $id, string $ignore = ''): string
    {
        return sodium_base642bin($string, $id, $ignore);
    }
    public static function sodium_bin2base64(string $string, int $id): string
    {
        return sodium_bin2base64($string, $id);
    }

    public static function sodium_bin2hex(string $string): string
    {
        return sodium_bin2hex($string);
    }

    public static function sodium_compare(string $left, string $right): int
    {
        return sodium_compare($left, $right);
    }

    public static function sodium_crypto_aead_aes256gcm_decrypt(
        string $ciphertext,
        string $additionalData,
        string $nonce,
        string $key,
    ): string|false {
        return sodium_crypto_aead_aes256gcm_decrypt($ciphertext, $additionalData, $nonce, $key);
    }

    public static function sodium_crypto_aead_aes256gcm_encrypt(
        string $message,
        string $additionalData,
        string $nonce,
        string $key,
    ): string {
        return sodium_crypto_aead_aes256gcm_encrypt($message, $additionalData, $nonce, $key);
    }

    public static function sodium_crypto_aead_chacha20poly1305_ietf_decrypt(
        string $ciphertext,
        string $additionalData,
        string $nonce,
        string $key,
    ): string|false {
        return sodium_crypto_aead_chacha20poly1305_ietf_decrypt($ciphertext, $additionalData, $nonce, $key);
    }

    public static function sodium_crypto_aead_chacha20poly1305_ietf_encrypt(
        string $message,
        string $additionalData,
        string $nonce,
        string $key,
    ): string {
        return sodium_crypto_aead_chacha20poly1305_ietf_encrypt($message, $additionalData, $nonce, $key);
    }

    public static function sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
        string $ciphertext,
        string $additionalData,
        string $nonce,
        string $key,
    ): string|false {
        return sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($ciphertext, $additionalData, $nonce, $key);
    }

    public static function sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        string $message,
        string $additionalData,
        string $nonce,
        string $key,
    ): string {
        return sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($message, $additionalData, $nonce, $key);
    }

    public static function sodium_crypto_auth(string $message, string $key): string
    {
        return sodium_crypto_auth($message, $key);
    }

    public static function sodium_crypto_auth_verify(string $mac, string $message, string $key): bool
    {
        return sodium_crypto_auth_verify($mac, $message, $key);
    }

    public static function sodium_crypto_box(string $message, string $nonce, string $keyPair): string
    {
        return sodium_crypto_box($message, $nonce, $keyPair);
    }

    public static function sodium_crypto_box_keypair(): string
    {
        return sodium_crypto_box_keypair();
    }

    public static function sodium_crypto_box_keypair_from_secretkey_and_publickey(string $secretKey, string $publicKey): string
    {
        return sodium_crypto_box_keypair_from_secretkey_and_publickey($secretKey, $publicKey);
    }

    public static function sodium_crypto_box_open(string $ciphertext, string $nonce, string $keyPair): string|false
    {
        return sodium_crypto_box_open($ciphertext, $nonce, $keyPair);
    }

    public static function sodium_crypto_box_publickey(string $keyPair): string
    {
        return sodium_crypto_box_publickey($keyPair);
    }

    public static function sodium_crypto_box_seal(string $message, string $publicKey): string
    {
        return sodium_crypto_box_seal($message, $publicKey);
    }

    public static function sodium_crypto_box_seal_open(string $ciphertext, string $keyPair): string|false
    {
        return sodium_crypto_box_seal_open($ciphertext, $keyPair);
    }

    public static function sodium_crypto_box_secretkey(string $keyPair): string
    {
        return sodium_crypto_box_secretkey($keyPair);
    }

    public static function sodium_crypto_box_seed_keypair(string $seed): string
    {
        return sodium_crypto_box_seed_keypair($seed);
    }

    public static function sodium_crypto_core_ristretto255_add(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_add($left, $right);
    }

    public static function sodium_crypto_core_ristretto255_scalar_add(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_scalar_add($left, $right);
    }

    public static function sodium_crypto_core_ristretto255_scalar_mul(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_scalar_mul($left, $right);
    }

    public static function sodium_crypto_core_ristretto255_scalar_sub(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_scalar_sub($left, $right);
    }

    public static function sodium_crypto_core_ristretto255_sub(string $left, string $right): string
    {
        return sodium_crypto_core_ristretto255_sub($left, $right);
    }

    public static function sodium_crypto_generichash(string $message, string $key = '', int $length = SODIUM_CRYPTO_GENERICHASH_BYTES): string
    {
        return sodium_crypto_generichash($message, $key, $length);
    }

    public static function sodium_crypto_generichash_final(string &$state, int $length = SODIUM_CRYPTO_GENERICHASH_BYTES): string
    {
        return sodium_crypto_generichash_final($state, $length);
    }

    public static function sodium_crypto_generichash_init(string $key = '', int $length = SODIUM_CRYPTO_GENERICHASH_BYTES): string
    {
        return sodium_crypto_generichash_init($key, $length);
    }

    public static function sodium_crypto_generichash_update(string &$state, string $message): bool
    {
        return sodium_crypto_generichash_update($state, $message);
    }

    public static function sodium_crypto_kdf_derive_from_key(int $subkeyLength, int $subkeyId, string $context, string $key): string
    {
        return sodium_crypto_kdf_derive_from_key($subkeyLength, $subkeyId, $context, $key);
    }

    public static function sodium_crypto_kx_client_session_keys(string $clientKeyPair, string $serverPublicKey): array
    {
        return sodium_crypto_kx_client_session_keys($clientKeyPair, $serverPublicKey);
    }

    public static function sodium_crypto_kx_keypair(): string
    {
        return sodium_crypto_kx_keypair();
    }

    public static function sodium_crypto_kx_seed_keypair(string $seed): string
    {
        return sodium_crypto_kx_seed_keypair($seed);
    }

    public static function sodium_crypto_kx_server_session_keys(string $serverKeyPair, string $clientPublicKey): array
    {
        return sodium_crypto_kx_server_session_keys($serverKeyPair, $clientPublicKey);
    }

    public static function sodium_crypto_onetimeauth(string $message, string $key): string
    {
        return sodium_crypto_onetimeauth($message, $key);
    }

    public static function sodium_crypto_onetimeauth_verify(string $mac, string $message, string $key): bool
    {
        return sodium_crypto_onetimeauth_verify($mac, $message, $key);
    }

    public static function sodium_crypto_pwhash(
        int $length,
        string $password,
        string $salt,
        int $opslimit,
        int $memlimit,
        int $algorithm = SODIUM_CRYPTO_PWHASH_ALG_DEFAULT,
    ): string {
        return sodium_crypto_pwhash($length, $password, $salt, $opslimit, $memlimit, $algorithm);
    }

    public static function sodium_crypto_pwhash_scryptsalsa208sha256(
        int $length,
        string $password,
        string $salt,
        int $opslimit,
        int $memlimit,
    ): string {
        return sodium_crypto_pwhash_scryptsalsa208sha256($length, $password, $salt, $opslimit, $memlimit);
    }

    public static function sodium_crypto_pwhash_scryptsalsa208sha256_str(
        string $password,
        int $opslimit = SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
        int $memlimit = SODIUM_CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE,
    ): string {
        return sodium_crypto_pwhash_scryptsalsa208sha256_str($password, $opslimit, $memlimit);
    }

    public static function sodium_crypto_pwhash_scryptsalsa208sha256_str_verify(string $hash, string $password): bool
    {
        return sodium_crypto_pwhash_scryptsalsa208sha256_str_verify($hash, $password);
    }

    public static function sodium_crypto_pwhash_str(
        string $password,
        int $opslimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        int $memlimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
    ): string {
        return sodium_crypto_pwhash_str($password, $opslimit, $memlimit);
    }

    public static function sodium_crypto_pwhash_str_needs_rehash(
        string $hash,
        int $opslimit = SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        int $memlimit = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
    ): bool {
        return sodium_crypto_pwhash_str_needs_rehash($hash, $opslimit, $memlimit);
    }

    public static function sodium_crypto_pwhash_str_verify(string $hash, string $password): bool
    {
        return sodium_crypto_pwhash_str_verify($hash, $password);
    }

    public static function sodium_crypto_scalarmult(string $secretKey, string $publicKey): string
    {
        return sodium_crypto_scalarmult($secretKey, $publicKey);
    }

    public static function sodium_crypto_scalarmult_base(string $secretKey): string
    {
        return sodium_crypto_scalarmult_base($secretKey);
    }

    public static function sodium_crypto_scalarmult_ristretto255(string $secretKey, string $publicKey): string
    {
        return sodium_crypto_scalarmult_ristretto255($secretKey, $publicKey);
    }

    public static function sodium_crypto_scalarmult_ristretto255_base(string $secretKey): string
    {
        return sodium_crypto_scalarmult_ristretto255_base($secretKey);
    }

    public static function sodium_crypto_secretbox(string $message, string $nonce, string $key): string
    {
        return sodium_crypto_secretbox($message, $nonce, $key);
    }

    public static function sodium_crypto_secretbox_open(string $ciphertext, string $nonce, string $key): string|false
    {
        return sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
    }

    public static function sodium_crypto_secretstream_xchacha20poly1305_init_pull(string $header, string $key): string
    {
        return sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
    }

    public static function sodium_crypto_secretstream_xchacha20poly1305_init_push(string $key): array
    {
        return sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
    }

    public static function sodium_crypto_secretstream_xchacha20poly1305_pull(
        string &$state,
        string $ciphertext,
        string $additionalData = '',
    ): array|false {
        return sodium_crypto_secretstream_xchacha20poly1305_pull($state, $ciphertext, $additionalData);
    }

    public static function sodium_crypto_secretstream_xchacha20poly1305_push(
        string &$state,
        string $message,
        string $additionalData = '',
        int $tag = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
    ): string {
        return sodium_crypto_secretstream_xchacha20poly1305_push($state, $message, $additionalData, $tag);
    }

    public static function sodium_crypto_secretstream_xchacha20poly1305_rekey(string &$state): void
    {
        sodium_crypto_secretstream_xchacha20poly1305_rekey($state);
    }

    public static function sodium_crypto_sign(string $message, string $secretKey): string
    {
        return sodium_crypto_sign($message, $secretKey);
    }

    public static function sodium_crypto_sign_detached(string $message, string $secretKey): string
    {
        return sodium_crypto_sign_detached($message, $secretKey);
    }

    public static function sodium_crypto_sign_keypair(): string
    {
        return sodium_crypto_sign_keypair();
    }

    public static function sodium_crypto_sign_keypair_from_secretkey_and_publickey(string $secretKey, string $publicKey): string
    {
        return sodium_crypto_sign_keypair_from_secretkey_and_publickey($secretKey, $publicKey);
    }

    public static function sodium_crypto_sign_open(string $signedMessage, string $publicKey): string|false
    {
        return sodium_crypto_sign_open($signedMessage, $publicKey);
    }

    public static function sodium_crypto_sign_publickey(string $keyPair): string
    {
        return sodium_crypto_sign_publickey($keyPair);
    }

    public static function sodium_crypto_sign_secretkey(string $keyPair): string
    {
        return sodium_crypto_sign_secretkey($keyPair);
    }

    public static function sodium_crypto_sign_seed_keypair(string $seed): string
    {
        return sodium_crypto_sign_seed_keypair($seed);
    }

    public static function sodium_crypto_sign_verify_detached(string $signature, string $message, string $publicKey): bool
    {
        return sodium_crypto_sign_verify_detached($signature, $message, $publicKey);
    }

    public static function sodium_hex2bin(string $string, string $ignore = ''): string
    {
        return sodium_hex2bin($string, $ignore);
    }

    public static function sodium_memcmp(string $left, string $right): int
    {
        return sodium_memcmp($left, $right);
    }

    public static function sodium_memzero(string &$string): void
    {
        sodium_memzero($string);
    }

    public static function sodium_randombytes_buf(int $length): string
    {
        return sodium_randombytes_buf($length);
    }

    public static function sodium_randombytes_uniform(int $upperBound): int
    {
        return sodium_randombytes_uniform($upperBound);
    }
}
