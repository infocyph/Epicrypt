<?php

namespace Infocyph\Epicrypt\Security;

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
        $parts = parse_url($url);

        $existing = [];
        if (isset($parts['query'])) {
            parse_str($parts['query'], $existing);
        }

        $merged = array_merge($existing, $parameters);
        $merged[$this->versionParam] = SignedUrlVersion::V1->value;
        if ($expiresAt !== null) {
            $merged[$this->expiresParam] = $expiresAt;
        }

        ksort($merged);
        $basePath = $this->buildBasePath($parts);
        $query = http_build_query($merged);

        $signature = Base64Url::encode(hash_hmac('sha256', $basePath . '?' . $query, $this->secret, true));
        $merged[$this->signatureParam] = $signature;

        return $basePath . '?' . http_build_query($merged);
    }

    public function verify(string $signedUrl): bool
    {
        $parts = parse_url($signedUrl);
        if (! is_array($parts)) {
            return false;
        }

        $query = [];
        parse_str((string) ($parts['query'] ?? ''), $query);

        $givenSignature = $query[$this->signatureParam] ?? null;
        if (! is_string($givenSignature) || $givenSignature === '') {
            return false;
        }

        if (isset($query[$this->versionParam])) {
            if (! is_numeric($query[$this->versionParam]) || (int) $query[$this->versionParam] !== SignedUrlVersion::V1->value) {
                return false;
            }
        }

        unset($query[$this->signatureParam]);
        if (isset($query[$this->expiresParam]) && time() > (int) $query[$this->expiresParam]) {
            return false;
        }

        ksort($query);
        $basePath = $this->buildBasePath($parts);
        $normalized = http_build_query($query);
        $computed = Base64Url::encode(hash_hmac('sha256', $basePath . '?' . $normalized, $this->secret, true));

        return SecureCompare::equals($computed, $givenSignature);
    }

    /**
     * @param array<string, mixed> $parts
     */
    private function buildBasePath(array $parts): string
    {
        $scheme = ($parts['scheme'] ?? 'https') . '://';
        $host = (string) ($parts['host'] ?? '');
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        $path = (string) ($parts['path'] ?? '/');

        return $scheme . $host . $port . $path;
    }
}
