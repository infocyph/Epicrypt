<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Internal\SecureCompare;
use Infocyph\Epicrypt\Internal\SecurityPolicy;

final class KeyRotationHelper
{
    /**
     * @param array<string, string>|KeyRing $keySet
     */
    public function resolve(string $kid, array|KeyRing $keySet): string
    {
        if ($keySet instanceof KeyRing) {
            $keySet = $keySet->keys();
        }

        if (!isset($keySet[$kid]) || $keySet[$kid] === '') {
            throw new KeyResolutionException('Unknown key identifier: ' . $kid);
        }

        return $keySet[$kid];
    }

    /**
     * @param array<string, string>|KeyRing $keySet
     */
    public function sign(string $payload, string $kid, array|KeyRing $keySet): string
    {
        $key = $this->resolve($kid, $keySet);

        return Base64Url::encode(hash_hmac(SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM, $payload, $key, true));
    }

    public function signWithKeyRing(string $payload, KeyRing $keyRing): string
    {
        $kid = $keyRing->activeKeyId();
        if ($kid === null) {
            throw new KeyResolutionException('Active key id is required when signing with a KeyRing.');
        }

        return $this->sign($payload, $kid, $keyRing);
    }

    /**
     * @param array<string, string>|KeyRing $keySet
     */
    public function verify(string $payload, string $signature, array|KeyRing $keySet, ?string $kid = null): bool
    {
        return $this->verifyResult($payload, $signature, $keySet, $kid)->verified;
    }

    /**
     * @param array<string, string>|KeyRing $keySet
     */
    public function verifyResult(string $payload, string $signature, array|KeyRing $keySet, ?string $kid = null): KeyVerificationResult
    {
        if ($kid !== null) {
            $computed = Base64Url::encode(hash_hmac(SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM, $payload, $this->resolve($kid, $keySet), true));

            return new KeyVerificationResult(
                SecureCompare::equals($computed, $signature),
                $kid,
                false,
            );
        }

        foreach (KeyCandidates::orderedEntries($keySet, 'All rotation keys must be non-empty strings.', 'At least one rotation key is required.') as $entry) {
            $computed = Base64Url::encode(hash_hmac(SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM, $payload, $entry['key'], true));
            if (SecureCompare::equals($computed, $signature)) {
                return new KeyVerificationResult(true, $entry['id'], !$entry['active']);
            }
        }

        return new KeyVerificationResult(false);
    }
}
