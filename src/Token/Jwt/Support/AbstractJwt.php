<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyVerificationResult;
use Infocyph\Epicrypt\Token\Contract\JwtTokenInterface;
use Infocyph\Epicrypt\Token\Jwt\JwtVerificationResult;
use Infocyph\Epicrypt\Token\Jwt\KeyResolver;
use Infocyph\Epicrypt\Token\Jwt\Validation\ExpectedJwtClaims;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtIssueClaims;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidationOptions;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidator;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
use Infocyph\Epicrypt\Token\Support\TokenAnyKey;
use Throwable;

abstract readonly class AbstractJwt implements JwtTokenInterface
{
    use JwtCommon;

    private ?ExpectedJwtClaims $normalizedExpectedClaims;

    private ?JwtValidator $validator;

    public function __construct(
        private string $keyFamily,
        private RegisteredClaims|ExpectedJwtClaims|null $expectedClaims,
        private JwtValidationOptions $validationOptions = new JwtValidationOptions(),
        private ClockInterface $clock = new SystemClock(),
    ) {
        if ($this->expectedClaims === null) {
            $this->normalizedExpectedClaims = null;
            $this->validator = null;

            return;
        }

        $this->normalizedExpectedClaims = $this->expectedClaims instanceof RegisteredClaims
            ? ExpectedJwtClaims::fromRegistered($this->expectedClaims)
            : $this->expectedClaims;

        $validatorOptions = new JwtValidationOptions(
            strictTyp: $this->validationOptions->strictTyp,
            requiredTyp: $this->validationOptions->requiredTyp,
            rejectCriticalHeaders: $this->validationOptions->rejectCriticalHeaders,
            rejectNoneAlgorithm: $this->validationOptions->rejectNoneAlgorithm,
            leewaySeconds: $this->normalizedExpectedClaims->leewaySeconds !== 0
                ? $this->normalizedExpectedClaims->leewaySeconds
                : $this->validationOptions->leewaySeconds,
            maxTokenAgeSeconds: $this->normalizedExpectedClaims->maxTokenAgeSeconds ?? $this->validationOptions->maxTokenAgeSeconds,
        );

        $this->validator = new JwtValidator(
            $this->normalizedExpectedClaims,
            options: $validatorOptions,
            clock: $this->clock,
        );
    }

    abstract protected function algorithmHeaderValue(mixed $algorithm): string;

    abstract protected function configuredAlgorithm(): mixed;

    abstract protected function parseAlgorithmFromHeader(string $algorithm): mixed;

    abstract protected function sign(string $input, string $resolvedKey): string;

    abstract protected function verifySignature(string $input, string $signature, string $resolvedKey, mixed $algorithm): bool;

    final public function decode(string $token, mixed $key): object
    {
        $result = $this->decodeResult($token, $key);
        if (!$result->verified) {
            throw new InvalidTokenException('JWT verification failed.');
        }

        return (object) $result->claims;
    }

    final public function decodeResult(string $token, mixed $key): JwtVerificationResult
    {
        $key = $this->requireSupportedKeyType($key);

        if ($this->expectedClaims === null) {
            throw new TokenException('Expected claims are required for JWT decoding.');
        }

        try {
            [$encodedHeader, $encodedPayload, $signature, $header, $payload] = JwtToken::parse($token);
            $this->validateHeader($header);

            $algorithm = $this->algorithmFromHeader($header);
            $resolvedKey = KeyResolver::resolve($key, $header['kid'] ?? null);

            if (!$this->verifySignature($encodedHeader . '.' . $encodedPayload, $signature, $resolvedKey, $algorithm)) {
                throw new InvalidTokenException('Signature verification failed.');
            }

            $this->requireValidator()->validate($payload);

            return new JwtVerificationResult(
                verified: true,
                claims: $payload,
                headers: $header,
                matchedKeyId: is_string($header['kid'] ?? null) ? $header['kid'] : null,
                usedFallbackKey: false,
                algorithm: is_string($header['alg'] ?? null) ? $header['alg'] : null,
            );
        } catch (ExpiredTokenException) {
            return new JwtVerificationResult(false, expired: true);
        } catch (InvalidClaimException $e) {
            $isNbfViolation = str_contains(strtolower($e->getMessage()), 'not active');

            return new JwtVerificationResult(false, notBeforeViolation: $isNbfViolation);
        } catch (UnsupportedAlgorithmException|KeyResolutionException|InvalidTokenException) {
            return new JwtVerificationResult(false);
        } catch (Throwable $e) {
            throw new InvalidTokenException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    final public function decodeWithAnyKey(string $token, iterable|KeyRing $keys): object
    {
        $result = $this->decodeWithAnyKeyResult($token, $keys);
        if (!$result->verified) {
            throw new InvalidTokenException(sprintf('JWT verification failed for every supplied %s key.', $this->keyFamily));
        }

        return (object) $result->claims;
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    final public function decodeWithAnyKeyResult(string $token, iterable|KeyRing $keys): JwtVerificationResult
    {
        $lastResult = new JwtVerificationResult(false);

        foreach ($this->orderedKeyEntries(
            $keys,
            sprintf('All %s JWT key candidates must be non-empty strings.', $this->keyFamily),
            sprintf('At least one %s JWT key candidate is required.', $this->keyFamily),
        ) as $entry) {
            $result = $this->decodeResult($token, $entry['key']);
            if ($result->verified) {
                return new JwtVerificationResult(
                    true,
                    $result->claims,
                    $result->headers,
                    $entry['id'],
                    !$entry['active'],
                    $result->expired,
                    $result->notBeforeViolation,
                    $result->algorithm,
                );
            }
            $lastResult = $result;
        }

        return $lastResult;
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    final public function encode(array $claims, mixed $key, array $headers = []): string
    {
        $key = $this->requireSupportedKeyType($key);

        $issueClaims = JwtIssueClaims::fromArray($claims);
        $keyId = $claims['kid'] ?? null;

        try {
            $resolvedKey = KeyResolver::resolve($key, $keyId);

            [$encodedHeader, $encodedPayload] = JwtToken::encodeSegments(
                $this->buildHeader($keyId, $headers),
                $this->buildPayload($issueClaims, $claims),
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
        return $this->verifyResult($token, $key)->verified;
    }

    final public function verifyResult(string $token, mixed $key): JwtVerificationResult
    {
        return $this->decodeResult($token, $key);
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
    private function buildPayload(JwtIssueClaims $issueClaims, array $claims): array
    {
        $payload = array_filter([
            'iss' => $issueClaims->issuer,
            'aud' => $issueClaims->audience,
            'sub' => $issueClaims->subject,
            'iat' => $this->clock->now(),
            'nbf' => $issueClaims->notBefore,
            'exp' => $issueClaims->expiresAt,
            'jti' => $issueClaims->jwtId,
        ], static fn(mixed $value): bool => $value !== null);

        return $payload + $this->removeReservedClaims($claims);
    }

    private function requireValidator(): JwtValidator
    {
        if ($this->validator === null) {
            throw new TokenException('Expected claims are required for JWT decoding.');
        }

        return $this->validator;
    }

    /**
     * @param array<string, mixed> $header
     */
    private function validateHeader(array $header): void
    {
        $alg = $header['alg'] ?? null;
        if (!is_string($alg) || $alg === '') {
            throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
        }

        if ($this->validationOptions->rejectNoneAlgorithm && strtolower($alg) === 'none') {
            throw new UnsupportedAlgorithmException('Algorithm "none" is not supported.');
        }

        if ($this->validationOptions->strictTyp) {
            $typ = $header['typ'] ?? null;
            if (!is_string($typ) || strtoupper($typ) !== strtoupper($this->validationOptions->requiredTyp)) {
                throw new InvalidTokenException('Invalid JWT typ header.');
            }
        }

        if ($this->validationOptions->rejectCriticalHeaders && array_key_exists('crit', $header)) {
            throw new InvalidTokenException('Unsupported JWT critical headers.');
        }

        if (array_key_exists('kid', $header) && (!is_string($header['kid']) || $header['kid'] === '')) {
            throw new InvalidTokenException('Invalid JWT kid header.');
        }
    }
}
