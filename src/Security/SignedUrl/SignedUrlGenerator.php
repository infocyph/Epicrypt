<?php

namespace Infocyph\Epicrypt\Security\SignedUrl;

use Infocyph\Epicrypt\Contract\SignedUrlGeneratorInterface;
use Infocyph\Epicrypt\Internal\Base64Url;

final readonly class SignedUrlGenerator implements SignedUrlGeneratorInterface
{
    public function __construct(
        private string $secret,
        private string $signatureParam = 'ep_sig',
        private string $expiresParam = 'ep_exp',
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
