<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Enum\SignedUrlVersion;
use Infocyph\Epicrypt\Internal\SecureCompare;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
use Infocyph\Epicrypt\Security\Contract\SignedUrlGeneratorInterface;
use Infocyph\Epicrypt\Security\Contract\SignedUrlVerifierInterface;
use Infocyph\Epicrypt\Security\Support\SignedUrlGuard;

/**
 * @phpstan-type QueryScalar bool|float|int|string
 * @phpstan-type QueryArray array<array-key, QueryScalar>
 * @phpstan-type QueryMap array<string, QueryScalar|QueryArray>
 */
final readonly class SignedUrl implements SignedUrlGeneratorInterface, SignedUrlVerifierInterface
{
    private const string METHOD_PARAM = 'ep_m';

    public function __construct(
        private string $secret,
        private string $signatureParam = 'ep_sig',
        private string $expiresParam = 'ep_exp',
        private string $versionParam = SecurityPolicy::SIGNED_URL_VERSION_PARAM,
        private ClockInterface $clock = new SystemClock(),
        private SignedUrlOptions $defaultOptions = new SignedUrlOptions(),
    ) {}

    /**
     * @param array<string, scalar|null> $parameters
     */
    public function generate(string $url, array $parameters = [], ?int $expiresAt = null, ?SignedUrlOptions $options = null): string
    {
        $options ??= $this->defaultOptions;

        [$parts, $existing] = $this->parseUrlWithQueryOrFail($url);
        $this->assertUrlPolicy($parts, $options, throwOnFailure: true);

        $merged = array_merge($existing, $parameters);
        $normalized = $this->normalizeQuery($merged, $options->allowArrayParameters);
        if ($normalized === null) {
            throw new ConfigurationException('Signed URL query parameters contain unsupported values.');
        }

        $merged = $normalized;
        $merged[$this->versionParam] = SignedUrlVersion::V1->value;
        if ($expiresAt !== null) {
            $merged[$this->expiresParam] = $expiresAt;
        }
        if ($options->method !== null) {
            $merged[self::METHOD_PARAM] = $options->method;
        }

        $merged = $this->normalizeQuery($merged, $options->allowArrayParameters);
        if ($merged === null) {
            throw new ConfigurationException('Signed URL query parameters contain unsupported values.');
        }

        $signatureBasePath = $this->buildSignatureBasePath($parts, $options);
        $signature = $this->computeSignature($signatureBasePath, $merged);
        $merged[$this->signatureParam] = $signature;

        return $this->buildDisplayBasePath($parts) . '?' . $this->buildQueryString($merged);
    }

    public function verify(string $signedUrl, ?SignedUrlOptions $options = null): bool
    {
        return $this->verifyResult($signedUrl, $options)->verified;
    }

    public function verifyResult(string $signedUrl, ?SignedUrlOptions $options = null): SignedUrlVerificationResult
    {
        $options ??= $this->defaultOptions;

        $parsed = $this->parseUrlWithQuery($signedUrl);
        if ($parsed === null) {
            return SignedUrlGuard::invalidSignatureResult();
        }
        [$parts, $query] = $parsed;
        if (!$this->assertUrlPolicy($parts, $options, throwOnFailure: false)) {
            return SignedUrlGuard::invalidSignatureResult();
        }

        $signatureData = SignedUrlGuard::extractSignatureData($query, $this->signatureParam, $this->versionParam);
        if ($signatureData === null) {
            return SignedUrlGuard::invalidSignatureResult();
        }
        $givenSignature = $signatureData['signature'];
        $version = $signatureData['version'];

        unset($query[$this->signatureParam]);
        $expiration = SignedUrlGuard::validateExpirationFromQuery($query, $this->expiresParam, $this->clock->now(), $version);
        if ($expiration !== null) {
            return $expiration;
        }
        $expiresAt = SignedUrlGuard::expiresAtFromQuery($query, $this->expiresParam);

        $methodValidation = SignedUrlGuard::validateMethodFromQuery($query, self::METHOD_PARAM, $options, $expiresAt, $version);
        if ($methodValidation !== null) {
            return $methodValidation;
        }

        $normalized = $this->normalizeQuery($query, $options->allowArrayParameters);
        if ($normalized === null) {
            return SignedUrlGuard::invalidSignatureResult($expiresAt, $version);
        }

        $signatureBasePath = $this->buildSignatureBasePath($parts, $options);
        $computed = $this->computeSignature($signatureBasePath, $normalized);

        $verified = SecureCompare::equals($computed, $givenSignature);

        return new SignedUrlVerificationResult(
            verified: $verified,
            invalidSignature: !$verified,
            expiresAt: $expiresAt,
            version: $version,
        );
    }

    /**
     * @param array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed} $parts
     */
    private function assertUrlPolicy(array $parts, SignedUrlOptions $options, bool $throwOnFailure): bool
    {
        return SignedUrlGuard::assertUrlPolicy($parts, $options, $throwOnFailure);
    }

    /**
     * @param array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed} $parts
     */
    private function buildDisplayBasePath(array $parts): string
    {
        [$path, $host, $scheme, $port] = $this->pathComponents($parts);

        if ($host === '' && $scheme === '') {
            return $path;
        }

        if ($scheme === '') {
            return '//' . $host . $port . $path;
        }

        return $scheme . '://' . $host . $port . $path;
    }

    /**
     * @param QueryMap $query
     */
    private function buildQueryString(array $query): string
    {
        return http_build_query($query, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed} $parts
     */
    private function buildSignatureBasePath(array $parts, SignedUrlOptions $options): string
    {
        [$path, $host, $scheme, $port] = $this->pathComponents($parts);

        if (!$options->bindHost && !$options->bindScheme) {
            return $path;
        }

        if (!$options->bindHost && $options->bindScheme) {
            return $scheme . '://' . $path;
        }

        if ($options->bindHost && !$options->bindScheme) {
            return '//' . $host . $port . $path;
        }

        return $scheme . '://' . $host . $port . $path;
    }

    /**
     * @param QueryMap $query
     */
    private function computeSignature(string $basePath, array $query): string
    {
        return Base64Url::encode(hash_hmac('sha256', $basePath . '?' . $this->buildQueryString($query), $this->secret, true));
    }

    /**
     * @param array<array-key, mixed> $value
     * @return array<array-key, scalar>|null
     */
    private function normalizeArrayValue(array $value): ?array
    {
        $normalized = [];
        foreach ($value as $key => $item) {
            if (is_scalar($item)) {
                $normalized[$key] = $item;

                continue;
            }

            return null;
        }

        ksort($normalized);

        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $query
     * @return QueryMap|null
     */
    private function normalizeQuery(array $query, bool $allowArrays): ?array
    {
        $normalized = [];

        foreach ($query as $key => $value) {
            if (!is_string($key) || $key === '') {
                continue;
            }

            if (is_scalar($value)) {
                $normalized[$key] = $value;

                continue;
            }

            if ($value === null) {
                continue;
            }

            if (!$allowArrays || !is_array($value)) {
                return null;
            }

            $normalizedArray = $this->normalizeArrayValue($value);
            if ($normalizedArray === null) {
                return null;
            }

            $normalized[$key] = $normalizedArray;
        }

        ksort($normalized);

        return $normalized;
    }

    /**
     * @return array{array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed}, QueryMap}|null
     */
    private function parseUrlWithQuery(string $url): ?array
    {
        $parts = parse_url($url);
        if (!is_array($parts)) {
            return null;
        }

        $query = [];
        if (isset($parts['query'])) {
            parse_str($parts['query'], $query);
        }

        $normalizedQuery = $this->normalizeQuery($query, allowArrays: true);
        if ($normalizedQuery === null) {
            return null;
        }

        return [$parts, $normalizedQuery];
    }

    /**
     * @return array{array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed}, QueryMap}
     */
    private function parseUrlWithQueryOrFail(string $url): array
    {
        $parsed = $this->parseUrlWithQuery($url);
        if ($parsed === null) {
            throw new ConfigurationException('Invalid URL provided for signing.');
        }

        return $parsed;
    }

    /**
     * @param array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed} $parts
     * @return array{string, string, string, string}
     */
    private function pathComponents(array $parts): array
    {
        $path = $this->pathFromParts($parts);
        $host = isset($parts['host']) && is_string($parts['host']) ? strtolower($parts['host']) : '';
        $scheme = isset($parts['scheme']) && is_string($parts['scheme']) ? strtolower($parts['scheme']) : '';
        $port = isset($parts['port']) && is_int($parts['port']) ? ':' . $parts['port'] : '';

        return [$path, $host, $scheme, $port];
    }

    /**
     * @param array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed} $parts
     */
    private function pathFromParts(array $parts): string
    {
        return isset($parts['path']) && is_string($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/';
    }
}
