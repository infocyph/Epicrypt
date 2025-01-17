<?php

namespace AbmmHasan\SafeGuard\JWT;

use ArrayAccess;
use Exception;
use SodiumException;

class Symmetric
{
    use Common;

    private array $algorithmT2A = [
        'HS256' => 'SHA256',
        'HS384' => 'SHA384',
        'HS512' => 'SHA512',
    ];
    private array $algorithmA2T = [
        'SHA256' => 'HS256',
        'SHA384' => 'HS384',
        'SHA512' => 'HS512',
    ];

    /**
     * Constructor: Set Secret
     *
     * @param string|array|ArrayAccess $secret Secret string to encrypt with
     * @throws Exception
     */
    public function __construct(string|array|ArrayAccess $secret)
    {
        $this->secret = $secret;
        $this->setAlgorithm('HS512');
        $this->payload['iat'] = time();
    }

    /**
     * Get JWT token for a given payload
     *
     * @param object|array|string $payload
     * @param mixed|null $keyId
     * @param array|object $header
     * @return string
     * @throws SodiumException
     */
    public function encode(object|array|string $payload, mixed $keyId = null, array|object $header = []): string
    {
        [$header, $payload] = $this->encodeHeaderNPayload($payload, $header, $keyId);

        return $header . "." . $payload . "." .
            $this->base64UrlEncode(
                hash_hmac($this->algorithm, $header . "." . $payload, $this->secret, true),
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
        [$parts, $header, $payload, $signature] = $this->decodeResource($token);

        if (hash_equals(
            $signature,
            hash_hmac($this->algorithmT2A[$header->alg], "$parts[0].$parts[1]", $this->secret, true),
        )) {
            if ($this->verifyRegister((array) $payload)) {
                return $payload;
            }
            throw new Exception("Token verification failed!");
        }
        throw new Exception("Signature verification failed!");
    }
}
