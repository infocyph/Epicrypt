<?php


namespace AbmmHasan\SafeGuard\JWT;


use Exception;

class Symmetric
{
    use Common;

    private string $algorithm = 'SHA512';

    private string $algorithmTitle = 'HS512';

    private array $algorithmT2A = [
        'HS256' => 'SHA256',
        'HS384' => 'SHA384',
        'HS512' => 'SHA512'
    ];
    private array $algorithmA2T = [
        'SHA256' => 'HS256',
        'SHA384' => 'HS384',
        'SHA512' => 'HS512'
    ];
//        'ES384' => array('openssl', 'SHA384'),
//        'ES256' => array('openssl', 'SHA256'),
//        'RS256' => array('openssl', 'SHA256'),
//        'RS384' => array('openssl', 'SHA384'),
//        'RS512' => array('openssl', 'SHA512'),
//        'EdDSA' => array('sodium_crypto', 'EdDSA'),

    /**
     * Get JWT token for a given payload
     *
     * @param object|array|string $payload
     * @param array|object $header
     * @return string
     * @throws Exception
     */
    public function encode(object|array|string $payload, array|object $header = []): string
    {
        if (count($this->payload) !== 7) {
            throw new Exception('Please, register predefined payload values first!');
        }
        $this->payload += (array)$payload;
        $header = self::base64UrlEncode(self::jsonEncode([
                'alg' => $this->algorithmTitle,
                'typ' => 'JWT'
            ] + (array)$header));
        $payload = self::base64UrlEncode(self::jsonEncode($this->payload));
        return $header . "." . $payload . "." .
            self::base64UrlEncode(
                hash_hmac($this->algorithm, $header . "." . $payload, $this->secret, true)
            );
    }

    /**
     * Get content (verified payload)
     *
     * @param string $token
     * @return object
     * @throws Exception
     */
    public function decode(string $token): object
    {
        $parts = array_filter(explode(".", $token));

        if (count($parts) !== 3) {
            throw new Exception('Invalid JWT string/segment!');
        }
        if (empty($header = self::jsonDecode(self::base64UrlDecode($parts[0])))) {
            throw new Exception('Invalid header!');
        }
        if (empty($payload = self::jsonDecode(self::base64UrlDecode($parts[1])))) {
            throw new Exception('Invalid payload/claims!');
        }
        if (empty($signature = self::base64UrlDecode($parts[2]))) {
            throw new Exception('Invalid signature!');
        }

        if (empty($header->alg) || !isset($this->algorithmT2A[$header->alg])) {
            throw new Exception("Invalid/Unsupported algorithm!");
        }

        if (hash_equals(
            $signature,
            hash_hmac($this->algorithmT2A[$header->alg], "$parts[0].$parts[1]", $this->secret, true)
        )) {
            if ($this->verifyRegister((array)$payload)) {
                return $payload;
            }
            throw new Exception("Token verification failed!");
        }
        throw new Exception("Signature verification failed!");
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
            throw new Exception("Invalid payload!");
        }
    }
}
