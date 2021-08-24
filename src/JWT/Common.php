<?php


namespace AbmmHasan\SafeGuard\JWT;


use ArrayAccess;
use Exception;
use SodiumException;

trait Common
{
    private string|array|ArrayAccess $secret;

    private array $payload;

    /**
     * Set hashing algorithm
     *
     * @param string $algorithm
     * @throws Exception
     */
    public function setAlgorithm(string $algorithm)
    {
        if (isset($this->algorithmT2A[$algorithm])) {
            $this->algorithmTitle = $algorithm;
            $this->algorithm = $this->algorithmT2A[$algorithm];
        } elseif (isset($this->algorithmA2T[$algorithm])) {
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
            throw new Exception("Invalid 'expirationTime' value! Should be, >= Current time & > 'notBefore' time.");
        }
        $this->payload['nbf'] = $notBefore;
        $this->payload['exp'] = $expirationTime;
    }

    /**
     * @param object|array|string $payload
     * @param array|object $header
     * @param mixed $keyId
     * @return array
     * @throws SodiumException|Exception
     */
    private function encodeHeaderNPayload(object|array|string $payload, array|object $header, mixed $keyId): array
    {
        if (count($this->payload) !== 7) {
            throw new Exception('Please, register predefined payload values first!');
        }
        $this->payload += (array)$payload;

        $preparedHeader = [
            'alg' => $this->algorithmTitle,
            'typ' => 'JWT'
        ];

        if (!is_null($keyId)) {
            $preparedHeader['kid'] = $keyId;
        }

        return [
            $this->base64UrlEncode($this->jsonEncode($preparedHeader + (array)$header)),
            $this->base64UrlEncode($this->jsonEncode($this->payload))
        ];
    }

    /**
     * @param string $token
     * @return array
     * @throws SodiumException|Exception
     */
    private function decodeResource(string $token): array
    {
        $parts = array_filter(explode(".", $token));

        if (count($parts) !== 3) {
            throw new Exception('Invalid JWT string/segment!');
        }

        if (empty($header = $this->jsonDecode($this->base64UrlDecode($parts[0])))) {
            throw new Exception('Invalid header!');
        }
        if (empty($payload = $this->jsonDecode($this->base64UrlDecode($parts[1])))) {
            throw new Exception('Invalid payload/claims!');
        }
        if (empty($signature = $this->base64UrlDecode($parts[2]))) {
            throw new Exception('Invalid signature!');
        }

        if (
            empty($header->alg) ||
            !isset($this->algorithmT2A[$header->alg]) ||
            $this->algorithmTitle !== $header->alg
        ) {
            throw new Exception("Invalid/Unsupported algorithm!");
        }

        if (is_array($this->secret) || $this->secret instanceof ArrayAccess) {
            if (!isset($header->kid) || !isset($this->secret[$header->kid])) {
                throw new Exception('"kid" invalid, lookup failed!');
            }
            $this->secret = $this->secret[$header->kid];
        }

        return [$parts, $header, $payload, $signature];
    }

    /**
     * Verify payload through register information
     *
     * @param $payload
     * @return bool
     * @throws Exception
     */
    private function verifyRegister($payload): bool
    {
        try {
            return !empty($payload) &&
                isset($payload['iss']) && $payload['sub'] == $this->payload['sub'] &&
                $payload['iat'] <= ($now = time()) && $payload['nbf'] > $payload['iat'] &&
                $payload['nbf'] < $payload['exp'] && $payload['exp'] >= $now &&
                in_array($this->payload['aud'], str_getcsv($payload['aud'])) &&
                (empty($this->payload['jti']) || $this->payload['jti'] === $payload['jti']);
        } catch (Exception $e) {
            throw new Exception("Invalid payload ({$e->getMessage()})!");
        }
    }

    /**
     * URL-safe Base64 Encode.
     *
     * @param string $input Input string
     * @return string Encoded string
     * @throws SodiumException
     */
    private function base64UrlEncode(string $input): string
    {
        return sodium_bin2base64($input, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * URL-safe Base64 Decode.
     *
     * @param string $input Encoded string
     * @return string Decoded string
     * @throws SodiumException
     */
    private function base64UrlDecode(string $input): string
    {
        return sodium_base642bin($input, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    /**
     * Encode into a JSON string.
     *
     * @param object|array $input Object or array
     * @return string JSON representation
     * @throws Exception
     */
    private function jsonEncode(object|array $input): string
    {
        $json = json_encode($input);
        if ($error = json_last_error()) {
            $this->jsonErrorParser($error);
        } elseif ($json === 'null') {
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
    private function jsonDecode(string $input): object
    {
        $result = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);

        if ($error = json_last_error()) {
            $this->jsonErrorParser($error);
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
    private function jsonErrorParser(int $error)
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
