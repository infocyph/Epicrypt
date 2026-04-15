<?php

namespace Infocyph\Epicrypt\JWT;

use ArrayAccess;
use Exception;
use SodiumException;

class Symmetric
{
    use Common;
    private array $algorithmA2T = [
        'SHA256' => 'HS256',
        'SHA384' => 'HS384',
        'SHA512' => 'HS512',
    ];

    private array $algorithmT2A = [
        'HS256' => 'SHA256',
        'HS384' => 'SHA384',
        'HS512' => 'SHA512',
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
     * Get content (verified payload)
     *
     * @throws Exception
     */
    public function decode(string $token): object
    {
        [$parts, $header, $payload, $signature] = $this->decodeResource($token);
        $secret = $this->resolveSecretByKeyId($header->kid ?? null);

        if (hash_equals(
            $signature,
            hash_hmac((string) $this->algorithmT2A[$header->alg], "$parts[0].$parts[1]", $secret, true),
        )) {
            if ($this->verifyRegister((array) $payload)) {
                return $payload;
            }
            throw new Exception("Token verification failed!");
        }
        throw new Exception("Signature verification failed!");
    }

    /**
     * Get JWT token for a given payload
     *
     * @param mixed|null $keyId
     * @throws SodiumException
     */
    public function encode(object|array|string $payload, mixed $keyId = null, array|object $header = []): string
    {
        [$header, $payload] = $this->encodeHeaderNPayload($payload, $header, $keyId);
        $secret = $this->resolveSecretByKeyId($keyId);

        return $header . "." . $payload . "."
            . $this->base64UrlEncode(
                hash_hmac((string) $this->algorithm, $header . "." . $payload, $secret, true),
            );
    }
}
