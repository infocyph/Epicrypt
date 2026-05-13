<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Enum\SignedUrlVersion;
use Infocyph\Epicrypt\Internal\SecureCompare;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
use Infocyph\Epicrypt\Security\Contract\SignedUrlGeneratorInterface;
use Infocyph\Epicrypt\Security\Contract\SignedUrlVerifierInterface;

final readonly class SignedUrl implements SignedUrlGeneratorInterface, SignedUrlVerifierInterface
{
    public function __construct(
        private string $secret,
        private string $signatureParam = 'ep_sig',
        private string $expiresParam = 'ep_exp',
        private string $versionParam = SecurityPolicy::SIGNED_URL_VERSION_PARAM,
    ) {}

    /**
     * @param array<string, scalar|null> $parameters
     */
    public function generate(string $url, array $parameters = [], ?int $expiresAt = null): string
    {
        [$parts, $existing] = $this->parseUrlWithQueryOrFail($url);

        $merged = array_merge($existing, $parameters);
        $merged[$this->versionParam] = SignedUrlVersion::V1->value;
        if ($expiresAt !== null) {
            $merged[$this->expiresParam] = $expiresAt;
        }

        $basePath = $this->buildBasePath($parts);
        $signature = $this->computeSignature($basePath, $merged);
        $merged[$this->signatureParam] = $signature;

        return $basePath . '?' . http_build_query($merged);
    }

    public function verify(string $signedUrl): bool
    {
        $parsed = $this->parseUrlWithQuery($signedUrl);
        if ($parsed === null) {
            return false;
        }
        [$parts, $query] = $parsed;

        $givenSignature = $query[$this->signatureParam] ?? null;
        if (!is_string($givenSignature) || $givenSignature === '') {
            return false;
        }

        if (isset($query[$this->versionParam])) {
            if (!is_numeric($query[$this->versionParam]) || (int) $query[$this->versionParam] !== SignedUrlVersion::V1->value) {
                return false;
            }
        }

        unset($query[$this->signatureParam]);
        if (isset($query[$this->expiresParam]) && time() > (int) $query[$this->expiresParam]) {
            return false;
        }

        $basePath = $this->buildBasePath($parts);
        $computed = $this->computeSignature($basePath, $query);

        return SecureCompare::equals($computed, $givenSignature);
    }

    /**
     * @param array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed} $parts
     */
    private function buildBasePath(array $parts): string
    {
        $scheme = isset($parts['scheme']) && is_string($parts['scheme']) && $parts['scheme'] !== ''
            ? $parts['scheme']
            : 'https';
        $host = isset($parts['host']) && is_string($parts['host']) ? $parts['host'] : '';
        $port = isset($parts['port']) && is_int($parts['port']) ? ':' . $parts['port'] : '';
        $path = isset($parts['path']) && is_string($parts['path']) && $parts['path'] !== '' ? $parts['path'] : '/';

        return $scheme . '://' . $host . $port . $path;
    }

    /**
     * @param array<string, scalar|null> $query
     */
    private function computeSignature(string $basePath, array $query): string
    {
        $query = array_filter($query, static fn(mixed $value): bool => $value !== null);
        ksort($query);

        return Base64Url::encode(hash_hmac('sha256', $basePath . '?' . http_build_query($query), $this->secret, true));
    }

    /**
     * @param array<mixed> $query
     * @return array<string, scalar>
     */
    private function normalizeQuery(array $query): array
    {
        $normalized = [];

        foreach ($query as $key => $value) {
            if (!is_string($key) || $key === '') {
                continue;
            }

            if (is_scalar($value)) {
                $normalized[$key] = $value;
            }
        }

        return $normalized;
    }

    /**
     * @return array{array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed}, array<string, scalar>}|null
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

        return [$parts, $this->normalizeQuery($query)];
    }

    /**
     * @return array{array{scheme?: mixed, host?: mixed, port?: mixed, path?: mixed}, array<string, scalar>}
     */
    private function parseUrlWithQueryOrFail(string $url): array
    {
        $parsed = $this->parseUrlWithQuery($url);
        if ($parsed === null) {
            throw new ConfigurationException('Invalid URL provided for signing.');
        }

        return $parsed;
    }
}
