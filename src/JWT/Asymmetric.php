<?php

namespace Infocyph\Epicrypt\JWT;

use ArrayAccess;
use Exception;
use Infocyph\Epicrypt\Asymmetric\Signature;
use Infocyph\Epicrypt\Misc\MBStringConverter;
use SodiumException;

class Asymmetric
{
    use Common;
    private array $algorithmA2T = [];

    private array $algorithmT2A = [
        'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384,
        'RS512' => OPENSSL_ALGO_SHA512,
        'ES256' => OPENSSL_ALGO_SHA256,
        'ES384' => OPENSSL_ALGO_SHA384,
        //        'ES512' => OPENSSL_ALGO_SHA512,
    ];

    private array $keyLength = [
        'ES256' => 64,
        'ES384' => 96,
        'ES512' => 132,
    ];

    /**
     * Constructor: Set Key
     *
     * @throws Exception
     */
    public function __construct(string|array|ArrayAccess $key, private $passphrase = null)
    {
        $this->secret = $key;
        $this->setAlgorithm('RS512');
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

        if (str_starts_with((string) $header->alg, 'ES')) {
            $signature = new MBStringConverter()->toAsn1($signature, $this->keyLength[$this->algorithmTitle]);
        }

        if (new Signature(true, $this->algorithm)
            ->verify("$parts[0].$parts[1]", $secret, $signature)) {
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
     * @throws Exception
     */
    public function encode(object|array|string $payload, mixed $keyId = null, array|object $header = []): string
    {
        [$header, $payload] = $this->encodeHeaderNPayload($payload, $header, $keyId);
        $secret = $this->resolveSecretByKeyId($keyId);

        $signature = new Signature(true, $this->algorithm)
            ->sign($header . "." . $payload, $secret, $this->passphrase);

        if (str_starts_with($this->algorithmTitle, 'ES')) {
            $signature = new MBStringConverter()->fromAsn1($signature, $this->keyLength[$this->algorithmTitle]);
        }

        return $header . "." . $payload . "." . $this->base64UrlEncode($signature);
    }
}
