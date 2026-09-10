<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Enum\SignedUrlVersion;
use Infocyph\Epicrypt\Internal\SecureCompare;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
use Infocyph\Epicrypt\Security\Support\SignedUrlGuard;
use Psr\Clock\ClockInterface;

/**
 * @phpstan-type QueryScalar bool|float|int|string
 * @phpstan-type QueryArray array<array-key, QueryScalar>
 * @phpstan-type QueryMap array<string, QueryScalar|QueryArray>
 */
final readonly class SignedUrl
{
    private const string ALGORITHM = 'sha256';

    private const string METHOD_PARAM = 'ep_m';

    public function __construct(
        #[\SensitiveParameter]
        private string|KeyRing $keys,
        private string $signatureParam = 'ep_sig',
        private string $expiresParam = 'ep_exp',
        private string $versionParam = SecurityPolicy::SIGNED_URL_VERSION_PARAM,
        private ClockInterface $clock = new SystemClock(),
        private SignedUrlOptions $defaultOptions = new SignedUrlOptions(),
        private string $keyIdParam = 'ep_kid',
    ) {
        if (is_string($this->keys)) {
            SecurityPolicy::assertHmacSecret($this->keys, 'Signed URL secret');
        }

        $reservedNames = [
            $this->signatureParam,
            $this->expiresParam,
            $this->versionParam,
            self::METHOD_PARAM,
            $this->keyIdParam,
        ];
        foreach ($reservedNames as $name) {
            if (preg_match('/\A[A-Za-z0-9_-]+\z/D', $name) !== 1) {
                throw new ConfigurationException('Signed URL reserved parameter names must use the safe query-key grammar.');
            }
        }
        if (count(array_unique($reservedNames)) !== count($reservedNames)) {
            throw new ConfigurationException('Signed URL reserved parameter names must be distinct.');
        }
    }

    /**
     * @param array<string, scalar|null> $parameters
     */
    public function generate(string $url, array $parameters = [], ?int $expiresAt = null, ?SignedUrlOptions $options = null): string
    {
        $options ??= $this->defaultOptions;

        [$parts, $existing] = $this->parseUrlWithQueryOrFail($url);
        $this->assertUrlPolicy($parts, $options, throwOnFailure: true);
        $this->assertNoReservedParameters($existing);
        $this->assertNoReservedParameters($parameters);
        if ($expiresAt !== null && $expiresAt <= $this->clock->now()->getTimestamp()) {
            throw new ConfigurationException('Signed URL expiration must be in the future.');
        }

        $merged = array_merge($existing, $parameters);
        $normalized = $this->normalizeQuery($merged, $options->allowArrayParameters);
        if ($normalized === null) {
            throw new ConfigurationException('Signed URL query parameters contain unsupported values.');
        }

        $merged = $normalized;
        $merged[$this->versionParam] = SignedUrlVersion::V2->value;
        if ($expiresAt !== null) {
            $merged[$this->expiresParam] = $expiresAt;
        }
        if ($options->method !== null) {
            $merged[self::METHOD_PARAM] = $options->method;
        }

        [$key, $keyId] = $this->writeKey();
        if ($keyId !== null) {
            $merged[$this->keyIdParam] = $keyId;
        }

        $merged = $this->normalizeQuery($merged, $options->allowArrayParameters);
        if ($merged === null) {
            throw new ConfigurationException('Signed URL query parameters contain unsupported values.');
        }

        $signatureBasePath = $this->buildSignatureBasePath($parts, $options);
        $signature = $this->computeSignature($signatureBasePath, $merged, $key);
        $merged[$this->signatureParam] = $signature;

        return $this->buildDisplayBasePath($parts) . '?' . $this->buildQueryString($merged);
    }

    public function verify(#[\SensitiveParameter] string $signedUrl, ?SignedUrlOptions $options = null): bool
    {
        return $this->verifyResult($signedUrl, $options)->verified;
    }

    public function verifyResult(#[\SensitiveParameter] string $signedUrl, ?SignedUrlOptions $options = null): SignedUrlVerificationResult
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
        $expiration = SignedUrlGuard::validateExpirationFromQuery($query, $this->expiresParam, $this->clock->now()->getTimestamp(), $version);
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

        $selected = $this->verificationKey($normalized, $expiresAt, $version);
        if ($selected instanceof SignedUrlVerificationResult) {
            return $selected;
        }
        [$key, $keyId, $usedFallbackKey] = $selected;

        $signatureBasePath = $this->buildSignatureBasePath($parts, $options);
        $computed = $this->computeSignature($signatureBasePath, $normalized, $key);
        $verified = SecureCompare::equals($computed, $givenSignature);

        return new SignedUrlVerificationResult(
            verified: $verified,
            invalidSignature: !$verified,
            expiresAt: $expiresAt,
            version: $version,
            matchedKeyId: $verified ? $keyId : null,
            usedFallbackKey: $verified && $usedFallbackKey,
        );
    }

    /**
     * @param QueryMap $parsed
     * @param array<string, true> $seenNames
     * @param array<string, string> $rootKinds
     * @param array{name: string, root: string, index: ?string, value: string} $component
     */
    private function appendQueryComponent(array &$parsed, array &$seenNames, array &$rootKinds, array $component): bool
    {
        if (isset($seenNames[$component['name']])) {
            return false;
        }
        $seenNames[$component['name']] = true;

        $root = $component['root'];
        $kind = $component['index'] === null ? 'scalar' : 'array';
        if (isset($rootKinds[$root]) && $rootKinds[$root] !== $kind) {
            return false;
        }
        $rootKinds[$root] = $kind;

        if ($component['index'] === null) {
            if (array_key_exists($root, $parsed)) {
                return false;
            }
            $parsed[$root] = $component['value'];

            return true;
        }

        $items = isset($parsed[$root]) && is_array($parsed[$root]) ? $parsed[$root] : [];
        if (array_key_exists($component['index'], $items)) {
            return false;
        }
        $items[$component['index']] = $component['value'];
        $parsed[$root] = $items;

        return true;
    }

    /** @param array<array-key, mixed> $query */
    private function assertNoReservedParameters(array $query): void
    {
        foreach ([
            $this->signatureParam,
            $this->expiresParam,
            $this->versionParam,
            self::METHOD_PARAM,
            $this->keyIdParam,
        ] as $reserved) {
            if (array_key_exists($reserved, $query)) {
                throw new ConfigurationException(sprintf('Signed URL input must not contain reserved parameter "%s".', $reserved));
            }
        }
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

        if (!$options->bindHost) {
            if (!$options->bindScheme) {
                return $path;
            }

            return $scheme . '://' . $path;
        }

        if (!$options->bindScheme) {
            return '//' . $host . $port . $path;
        }

        return $scheme . '://' . $host . $port . $path;
    }

    /**
     * @param QueryMap $query
     */
    private function computeSignature(
        string $basePath,
        array $query,
        #[\SensitiveParameter]
        string $key,
    ): string {
        return Base64Url::encode(hash_hmac(self::ALGORITHM, $basePath . '?' . $this->buildQueryString($query), $key, true));
    }

    /** @return array{name: string, root: string, index: ?string, value: string}|null */
    private function decodeQueryComponent(string $pair): ?array
    {
        if ($pair === '') {
            return null;
        }

        [$encodedName, $encodedValue] = array_pad(explode('=', $pair, 2), 2, '');
        if (!$this->hasValidPercentEncoding($encodedName) || !$this->hasValidPercentEncoding($encodedValue)) {
            return null;
        }

        $name = rawurldecode($encodedName);
        if (preg_match('/\A([A-Za-z0-9_-]+)(?:\[([A-Za-z0-9_-]+)\])?\z/D', $name, $matches) !== 1) {
            return null;
        }

        return [
            'name' => $name,
            'root' => $matches[1],
            'index' => $matches[2] ?? null,
            'value' => rawurldecode($encodedValue),
        ];
    }

    private function hasValidPercentEncoding(string $value): bool
    {
        return preg_match('/%(?![0-9A-Fa-f]{2})/', $value) !== 1;
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
            if (!is_string($key) || preg_match('/\A[A-Za-z0-9_-]+\z/D', $key) !== 1) {
                return null;
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

    /** @return QueryMap|null */
    private function parseRawQuery(string $query): ?array
    {
        if ($query === '') {
            return [];
        }

        $parsed = [];
        $seenNames = [];
        $rootKinds = [];
        foreach (explode('&', $query) as $pair) {
            $component = $this->decodeQueryComponent($pair);
            if ($component === null || !$this->appendQueryComponent($parsed, $seenNames, $rootKinds, $component)) {
                return null;
            }
        }

        return $parsed;
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

        if (isset($parts['fragment'])) {
            return null;
        }

        $query = isset($parts['query']) ? $this->parseRawQuery($parts['query']) : [];
        if ($query === null) {
            return null;
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

    /**
     * @param QueryMap $query
     * @return array{string, ?string, bool}|SignedUrlVerificationResult
     */
    private function verificationKey(array $query, ?int $expiresAt, ?int $version): array|SignedUrlVerificationResult
    {
        if (is_string($this->keys)) {
            return [$this->keys, null, false];
        }

        $keyId = $query[$this->keyIdParam] ?? null;
        if (!is_string($keyId) || preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $keyId) !== 1) {
            return new SignedUrlVerificationResult(
                verified: false,
                invalidSignature: true,
                expiresAt: $expiresAt,
                version: $version,
                keyNotUsable: true,
            );
        }

        $entry = $this->keys->resolveForVerification($keyId, KeyPurpose::SIGNED_URL, self::ALGORITHM);
        if (!$entry instanceof KeyRingEntry) {
            return new SignedUrlVerificationResult(
                verified: false,
                invalidSignature: true,
                expiresAt: $expiresAt,
                version: $version,
                keyNotUsable: true,
            );
        }

        try {
            SecurityPolicy::assertHmacSecret($entry->key, 'Signed URL key');
        } catch (ConfigurationException) {
            return new SignedUrlVerificationResult(
                verified: false,
                invalidSignature: true,
                expiresAt: $expiresAt,
                version: $version,
                keyNotUsable: true,
            );
        }

        return [$entry->key, $entry->id, $entry->status === KeyStatus::FALLBACK];
    }

    /** @return array{string, ?string} */
    private function writeKey(): array
    {
        if (is_string($this->keys)) {
            return [$this->keys, null];
        }

        $entry = $this->keys->activeForWrite(KeyPurpose::SIGNED_URL, self::ALGORITHM);
        SecurityPolicy::assertHmacSecret($entry->key, 'Signed URL key');

        return [$entry->key, $entry->id];
    }
}
