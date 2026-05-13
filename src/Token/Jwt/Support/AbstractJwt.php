<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyVerificationResult;
use Infocyph\Epicrypt\Token\Contract\JwtTokenInterface;
use Infocyph\Epicrypt\Token\Jwt\KeyResolver;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidator;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
use Infocyph\Epicrypt\Token\Support\TokenAnyKey;
use Throwable;

abstract readonly class AbstractJwt implements JwtTokenInterface
{
    use JwtCommon;

    public function __construct(
        private string $keyFamily,
        private ?RegisteredClaims $expectedClaims,
    ) {}

    abstract protected function algorithmHeaderValue(mixed $algorithm): string;

    abstract protected function configuredAlgorithm(): mixed;

    abstract protected function parseAlgorithmFromHeader(string $algorithm): mixed;

    abstract protected function sign(string $input, string $resolvedKey): string;

    abstract protected function verifySignature(string $input, string $signature, string $resolvedKey, mixed $algorithm): bool;

    final public function decode(string $token, mixed $key): object
    {
        $key = $this->requireSupportedKeyType($key);

        if ($this->expectedClaims === null) {
            throw new TokenException('Expected claims are required for JWT decoding.');
        }

        try {
            [$encodedHeader, $encodedPayload, $signature, $header, $payload] = JwtToken::parse($token);

            $algorithm = $this->algorithmFromHeader($header);
            $resolvedKey = KeyResolver::resolve($key, $header['kid'] ?? null);

            if (!$this->verifySignature($encodedHeader . '.' . $encodedPayload, $signature, $resolvedKey, $algorithm)) {
                throw new InvalidTokenException('Signature verification failed.');
            }

            new JwtValidator($this->expectedClaims)->validate($payload);

            return (object) $payload;
        } catch (UnsupportedAlgorithmException|KeyResolutionException|InvalidTokenException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidTokenException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    final public function decodeWithAnyKey(string $token, iterable|KeyRing $keys): object
    {
        return TokenAnyKey::decode(
            $this->orderedKeys(
                $keys,
                sprintf('All %s JWT key candidates must be non-empty strings.', $this->keyFamily),
                sprintf('At least one %s JWT key candidate is required.', $this->keyFamily),
            ),
            fn(string $candidateKey): object => $this->decode($token, $candidateKey),
            fn(?Throwable $previous): Throwable => new InvalidTokenException(
                sprintf('JWT verification failed for every supplied %s key.', $this->keyFamily),
                0,
                $previous,
            ),
        );
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    final public function encode(array $claims, mixed $key, array $headers = []): string
    {
        $key = $this->requireSupportedKeyType($key);

        $registeredClaims = RegisteredClaims::fromArray($claims);
        [$notBefore, $expiresAt] = $this->extractTemporalClaims($claims);
        $keyId = $claims['kid'] ?? null;

        try {
            $resolvedKey = KeyResolver::resolve($key, $keyId);

            [$encodedHeader, $encodedPayload] = JwtToken::encodeSegments(
                $this->buildHeader($keyId, $headers),
                $this->buildPayload($registeredClaims, $notBefore, $expiresAt, $claims),
            );

            $signature = $this->sign($encodedHeader . '.' . $encodedPayload, $resolvedKey);

            return $encodedHeader . '.' . $encodedPayload . '.' . Base64Url::encode($signature);
        } catch (UnsupportedAlgorithmException|InvalidClaimException|KeyResolutionException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new TokenException("JWT encoding failed: {$e->getMessage()}", 0, $e);
        }
    }

    final public function verify(string $token, mixed $key): bool
    {
        try {
            $this->decode($token, $key);

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    final public function verifyWithAnyKey(string $token, iterable|KeyRing $keys): bool
    {
        return $this->verifyWithAnyKeyResult($token, $keys)->verified;
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    final public function verifyWithAnyKeyResult(string $token, iterable|KeyRing $keys): KeyVerificationResult
    {
        return TokenAnyKey::verifyResult(
            $this->orderedKeyEntries(
                $keys,
                sprintf('All %s JWT key candidates must be non-empty strings.', $this->keyFamily),
                sprintf('At least one %s JWT key candidate is required.', $this->keyFamily),
            ),
            fn(string $candidateKey): bool => $this->verify($token, $candidateKey),
        );
    }

    /**
     * @param array<string, mixed> $header
     */
    private function algorithmFromHeader(array $header): mixed
    {
        if (!isset($header['alg']) || !is_string($header['alg'])) {
            throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
        }

        $parsed = $this->parseAlgorithmFromHeader($header['alg']);
        if ($parsed !== $this->configuredAlgorithm()) {
            throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
        }

        return $parsed;
    }

    /**
     * @param array<string, mixed> $headers
     * @return array<string, mixed>
     */
    private function buildHeader(mixed $keyId, array $headers): array
    {
        $configuredAlgorithm = $this->configuredAlgorithm();

        $header = [
            'alg' => $this->algorithmHeaderValue($configuredAlgorithm),
            'typ' => 'JWT',
        ];

        if ($keyId !== null) {
            if (!is_string($keyId) || $keyId === '') {
                throw new InvalidClaimException('Claim "kid" must be a non-empty string when provided.');
            }

            $header['kid'] = $keyId;
        }

        return $header + $headers;
    }

    /**
     * @param array<string, mixed> $claims
     * @return array<string, mixed>
     */
    private function buildPayload(RegisteredClaims $registeredClaims, int $notBefore, int $expiresAt, array $claims): array
    {
        $payload = [
            'iss' => $registeredClaims->issuer,
            'aud' => $registeredClaims->audience,
            'sub' => $registeredClaims->subject,
            'iat' => time(),
            'nbf' => $notBefore,
            'exp' => $expiresAt,
        ];

        if ($registeredClaims->jwtId !== null) {
            $payload['jti'] = $registeredClaims->jwtId;
        }

        return $payload + $this->removeReservedClaims($claims);
    }
}
