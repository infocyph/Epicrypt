<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class RemoteJwksConfiguration
{
    public function __construct(
        public string $issuer,
        public ?string $jwksUri = null,
        public int $minimumTtl = 60,
        public int $maximumTtl = 3600,
        public int $staleTtl = 300,
        public int $maximumResponseBytes = 1_048_576,
        public int $maximumKeys = 100,
        public bool $allowHttp = false,
        /** @var list<string> */
        public array $allowedJwksHosts = [],
    ) {
        $this->validateUrl($issuer);
        foreach ($this->allowedJwksHosts as $host) {
            if ($host === '' || strtolower($host) !== $host || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
                throw new ConfigurationException('Remote JWKS allowed hosts must be lowercase DNS hostnames.');
            }
        }
        if ($jwksUri !== null) {
            $this->validateJwksUrl($jwksUri);
        }
        if ($minimumTtl < 1 || $maximumTtl < $minimumTtl || $staleTtl < 0
            || $maximumResponseBytes < 1024 || $maximumResponseBytes > 10_485_760
            || $maximumKeys < 1 || $maximumKeys > 1_000) {
            throw new ConfigurationException('Remote JWKS bounds are invalid.');
        }
    }

    public function discoveryUri(): string
    {
        return rtrim($this->issuer, '/') . '/.well-known/openid-configuration';
    }

    public function validateJwksUrl(string $url): void
    {
        $this->validateUrl($url);
        $issuerHost = $this->normalizedHost($this->issuer);
        $jwksHost = $this->normalizedHost($url);
        if ($issuerHost === null || $jwksHost === null) {
            throw new ConfigurationException('Remote JWKS host validation failed.');
        }
        if (!hash_equals($issuerHost, $jwksHost) && !in_array($jwksHost, $this->allowedJwksHosts, true)) {
            throw new ConfigurationException('Remote JWKS host must match the issuer or be explicitly allowed.');
        }
    }

    public function validateUrl(string $url): void
    {
        $parts = parse_url($url);
        $scheme = is_array($parts) ? ($parts['scheme'] ?? null) : null;
        $host = $this->normalizedHost($url);
        $validHost = is_string($host)
            && (filter_var($host, FILTER_VALIDATE_IP) !== false
                || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false);
        if (!is_string($scheme) || !$validHost
            || (!$this->allowHttp && strtolower($scheme) !== 'https')
            || ($this->allowHttp && !in_array(strtolower($scheme), ['https', 'http'], true))
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || $host === 'localhost' || $this->isPrivateIp($host)) {
            throw new ConfigurationException('Remote JOSE URL is not an allowed absolute HTTPS URL.');
        }
    }

    private function isPrivateIp(string $host): bool
    {
        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    private function normalizedHost(string $url): ?string
    {
        $host = parse_url($url, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? strtolower(trim($host, '[]')) : null;
    }
}
