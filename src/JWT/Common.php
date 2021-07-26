<?php


namespace AbmmHasan\SafeGuard\JWT;


use Exception;

trait Common
{
    private string $secret = '';

    private array $payload;

    /**
     * Constructor: Set Secret
     *
     * @param string $secret Secret string to encrypt with
     */
    public function __construct(string $secret)
    {
        $this->secret = $secret;
        $this->payload['iat'] = time();
    }

    /**
     * Set hashing algorithm
     *
     * @param string $algorithm
     * @throws Exception
     */
    public function setAlgorithm(string $algorithm)
    {
        if (in_array($algorithm, $this->algorithmA2T)) {
            $this->algorithmTitle = $algorithm;
            $this->algorithm = $this->algorithmT2A[$algorithm];
        } elseif (in_array($algorithm, $this->algorithmT2A)) {
            $this->algorithmTitle = $this->algorithmA2T[$algorithm];
            $this->algorithm = $algorithm;
        } else {
            throw new Exception(
                "Invalid algorithm! Can by either of '" .
                implode(", ", $this->algorithmA2T + $this->algorithmT2A) . "'!"
            );
        }
    }

    /**
     * Register predefined JWT keys (general claims)
     *
     * https://tools.ietf.org/html/rfc7519#page-9
     *
     * @param string $issuer the name or identifier of the issuer
     * @param string $audience Specify the audience of the JWT (CSV formatted)
     * @param string $subject Type of JWT payload, local/global identifier for what this JWT is for
     * @param string|null $jwtID (optional) an unique token, usable as validator
     */
    public function registerClaims(string $issuer, string $audience, string $subject, string $jwtID = null)
    {
        $this->payload['iss'] = $issuer;
        $this->payload['aud'] = $audience;
        $this->payload['sub'] = $subject;
        $this->payload['jti'] = $jwtID;
    }

    /**
     * Register predefined JWT keys (time based claims)
     *
     * Required during Token generation only
     *
     * https://tools.ietf.org/html/rfc7519#page-9
     *
     * @param int $notBefore a timestamp of when the token should start being considered valid.
     * @param int $expirationTime a timestamp of when the token should cease to be valid.
     * @throws Exception
     */
    public function registerTime(int $notBefore, int $expirationTime)
    {
        if ($notBefore < $this->payload['iat']) {
            throw new Exception("Invalid 'notBefore' value! Should be >= Current time.");
        }
        if ($expirationTime < $this->payload['iat'] || $expirationTime <= $notBefore) {
            throw new Exception("Invalid 'expirationTime' value! Should be, >= Current time & <= 'notBefore' time.");
        }
        $this->payload['nbf'] = $notBefore;
        $this->payload['exp'] = $expirationTime;
    }

    /**
     * URL-safe Base64 Encode.
     *
     * @param string $input Input string
     * @return string Encoded string
     */
    private function base64UrlEncode(string $input): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($input));
    }

    /**
     * URL-safe Base64 Decode.
     *
     * @param string $input Encoded string
     * @return string Decoded string
     */
    private function base64UrlDecode(string $input): string
    {
        return base64_decode(str_replace(['-', '_'], ['+', '/'], $input), true);
    }

    /**
     * Encode into a JSON string.
     *
     * @param object|array $input Object or array
     * @return string JSON representation
     * @throws Exception
     */
    private static function jsonEncode(object|array $input): string
    {
        $json = json_encode($input);
        if ($error = json_last_error()) {
            self::jsonErrorParser($error);
        } elseif ($json === 'null' && $input !== null) {
            throw new Exception('Null result with non-null input');
        }
        return $json;
    }

    /**
     * Decode a JSON string.
     *
     * @param string $input JSON string
     * @return object Object representation of JSON string
     * @throws Exception
     */
    private static function jsonDecode(string $input): object
    {
        $result = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);

        if ($error = json_last_error()) {
            self::jsonErrorParser($error);
        } elseif ($result === null && $input !== 'null') {
            throw new Exception('Null result with non-null input');
        }
        return $result;
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $error An error number from json_last_error()
     * @return void
     * @throws Exception
     */
    private static function jsonErrorParser(int $error)
    {
        throw new Exception(
            [
                JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
                JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
                JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
                JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
                JSON_ERROR_UTF8 => 'Malformed UTF-8 characters'
            ][$error] ?? "Unknown JSON error ($error)!"
        );
    }
}
