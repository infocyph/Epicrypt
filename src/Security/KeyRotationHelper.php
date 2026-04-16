<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\SecureCompare;
use Infocyph\Epicrypt\Internal\SecurityPolicy;

final class KeyRotationHelper
{
    /**
     * @param array<string, string> $keySet
     */
    public function resolve(string $kid, array $keySet): string
    {
        if (!isset($keySet[$kid]) || $keySet[$kid] === '') {
            throw new KeyResolutionException('Unknown key identifier: ' . $kid);
        }

        return $keySet[$kid];
    }

    /**
     * @param array<string, string> $keySet
     */
    public function sign(string $payload, string $kid, array $keySet): string
    {
        $key = $this->resolve($kid, $keySet);

        return Base64Url::encode(hash_hmac(SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM, $payload, $key, true));
    }

    /**
     * @param array<string, string> $keySet
     */
    public function verify(string $payload, string $signature, array $keySet, ?string $kid = null): bool
    {
        if ($kid !== null) {
            $computed = Base64Url::encode(hash_hmac(SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM, $payload, $this->resolve($kid, $keySet), true));

            return SecureCompare::equals($computed, $signature);
        }

        foreach ($keySet as $key) {
            $computed = Base64Url::encode(hash_hmac(SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM, $payload, $key, true));
            if (SecureCompare::equals($computed, $signature)) {
                return true;
            }
        }

        return false;
    }
}
