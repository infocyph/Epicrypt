<?php

namespace Infocyph\Epicrypt\Sodium;

use Infocyph\Epicrypt\Exceptions\SodiumCryptoException;
use SodiumException;

trait Base64Codec
{
    /**
     * Encodes a given binary string into a Base64 string.
     *
     * @param  string  $data  The binary data to be encoded.
     * @return string The Base64 encoded string.
     */
    private function bin2base64(#[\SensitiveParameter] string $data): string
    {
        return base64_encode($data);
    }

    /**
     * Decodes a given Base64 string into a binary string.
     *
     * @param  string  $data  The Base64 encoded string to be decoded.
     * @return string The binary data.
     *
     * @throws SodiumCryptoException Invalid Base64 string.
     */
    private function base642bin(#[\SensitiveParameter] string $data): string
    {
        $data = base64_decode($data, true);
        if ($data === false) {
            throw new SodiumCryptoException('Invalid Base64 encoded message.');
        }

        return $data;
    }

    /**
     * Encodes a given binary string into a Base64 string using the original
     * variant with no padding.
     *
     * @param  string  $data  The binary data to be encoded.
     * @return string The Base64 encoded string.
     *
     * @throws SodiumException
     *
     * @internal This function is only available if the Sodium extension is
     *           installed and compiled with support for the original variant
     *           of the Base64 algorithm.
     */
    private function bin2base64Sodium(#[\SensitiveParameter] string $data): string
    {
        return sodium_bin2base64($data, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }

    /**
     * Decodes a given Base64 string into a binary string using the original
     * variant with no padding.
     *
     * @param  string  $data  The Base64 encoded string to be decoded.
     * @return string The binary data.
     *
     * @throws SodiumException
     *
     * @internal This function is only available if the Sodium extension is
     *           installed and compiled with support for the original variant
     *           of the Base64 algorithm.
     */
    private function base642binSodium(#[\SensitiveParameter] string $data): string
    {
        return sodium_base642bin($data, SODIUM_BASE64_VARIANT_ORIGINAL_NO_PADDING);
    }
}
