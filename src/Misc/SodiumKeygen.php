<?php

namespace AbmmHasan\SafeGuard\Misc;

use Exception;
use SodiumException;

class SodiumKeygen
{
    /**
     * Sodium Session Exchange keygen (Asymmetric)
     *
     * @param string|null $seed (optional) Seed for deterministic key generation
     * @return object Key resource
     * @throws SodiumException|Exception
     */
    public static function sessionExchange(string $seed = null): object
    {
        if (!is_null($seed)) {
            if (($length = strlen($seed)) !== 32) {
                throw new Exception("Invalid Seed size (Expected: 32B, Found: {$length}B)!");
            }
            $keypair = sodium_crypto_kx_seed_keypair($seed);
        } else {
            $keypair = sodium_crypto_kx_keypair();
        }

        return (object)[
            'keypair' => $keypair,
            'private' => sodium_crypto_kx_secretkey($keypair),
            'public' => sodium_crypto_kx_publickey($keypair)
        ];
    }

    /**
     * Sodium Sign & Detached Sign keygen (Asymmetric)
     *
     * @param string|null $seed (optional) Seed for deterministic key generation
     * @return object Key resource
     * @throws SodiumException|Exception
     */
    public static function sign(string $seed = null): object
    {
        if (!is_null($seed)) {
            if (($length = strlen($seed)) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
                throw new Exception(
                    "Invalid Seed size (Expected: " . SODIUM_CRYPTO_SIGN_SEEDBYTES . "B, Found: {$length}B)!"
                );
            }
            $keypair = sodium_crypto_sign_seed_keypair($seed);
        } else {
            $keypair = sodium_crypto_sign_keypair();
        }

        return (object)[
            'private' => sodium_crypto_sign_secretkey($keypair),
            'public' => sodium_crypto_sign_publickey($keypair)
        ];
    }

    /**
     * Sodium Box & Seal keygen (Asymmetric)
     *
     * @param string|null $seed (optional) Seed for deterministic key generation
     * @return object Key resource
     * @throws SodiumException|Exception
     */
    public static function box(string $seed = null): object
    {
        if (!is_null($seed)) {
            if ($length = strlen($seed) !== 32) {
                throw new Exception("Invalid Seed size (Expected: 32B, Found: {$length}B)!");
            }
            $keypair = sodium_crypto_box_seed_keypair($seed);
        } else {
            $keypair = sodium_crypto_box_keypair();
        }

        return (object)[
            'private' => sodium_crypto_box_secretkey($keypair),
            'public' => sodium_crypto_box_publickey($keypair),
            'nonce' => random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES)
        ];
    }

    /**
     * Sodium Auth keygen (Symmetric)
     *
     * @return string Key resource
     */
    public static function getSecret(): string
    {
        return sodium_crypto_auth_keygen();
    }

    /**
     * Sodium Secret Box keygen (Symmetric)
     *
     * @return object Key resource
     * @throws Exception
     */
    public static function secretBox(): object
    {
        return (object)[
            'key' => sodium_crypto_secretbox_keygen(),
            'nonce' => random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES)
        ];
    }
}
