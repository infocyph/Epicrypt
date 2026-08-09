<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;

/** @internal RFC 7638 and RFC 9278 canonicalization boundary. */
final class JwkThumbprint
{
    /** @param array<string, mixed> $jwk */
    public function calculate(array $jwk): string
    {
        $members = match ($jwk['kty'] ?? null) {
            'EC' => $this->requiredMembers($jwk, ['crv', 'kty', 'x', 'y']),
            'OKP' => $this->requiredMembers($jwk, ['crv', 'kty', 'x']),
            'RSA' => $this->requiredMembers($jwk, ['e', 'kty', 'n']),
            'oct' => $this->requiredMembers($jwk, ['k', 'kty']),
            default => throw new KeyResolutionException('Unsupported JWK type for thumbprint generation.'),
        };

        return Base64Url::encode(hash('sha256', Json::encode($members), true));
    }

    /** @param array<string, mixed> $jwk */
    public function uri(array $jwk): string
    {
        return 'urn:ietf:params:oauth:jwk-thumbprint:sha-256:' . $this->calculate($jwk);
    }

    /**
     * @param array<string, mixed> $jwk
     * @param list<string> $names
     * @return array<string, string>
     */
    private function requiredMembers(array $jwk, array $names): array
    {
        $members = [];
        foreach ($names as $name) {
            $value = $jwk[$name] ?? null;
            if (!is_string($value) || $value === '') {
                throw new KeyResolutionException(sprintf('JWK thumbprint requires non-empty %s.', $name));
            }
            $members[$name] = $value;
        }

        return $members;
    }
}
