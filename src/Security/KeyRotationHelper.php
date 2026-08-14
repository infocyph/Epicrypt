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
    public function resolve(string $kid, #[\SensitiveParameter] array|KeyRing $keySet): string
    {
        if ($keySet instanceof KeyRing) {
            $entry = $keySet->resolveForVerification(
                $kid,
                KeyPurpose::KEY_ROTATION,
                SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM,
            );
            if ($entry === null) {
                throw new KeyResolutionException('Unknown or ineligible key identifier: ' . $kid);
            }

            SecurityPolicy::assertHmacSecret($entry->key, 'Key-rotation secret');

            return $entry->key;
        }

        if (!isset($keySet[$kid]) || $keySet[$kid] === '') {
            throw new KeyResolutionException('Unknown key identifier: ' . $kid);
        }

        SecurityPolicy::assertHmacSecret($keySet[$kid], 'Key-rotation secret');

        return $keySet[$kid];
    }

    /**
     * @param array<string, string>|KeyRing $keySet
     */
    public function sign(string $payload, string $kid, #[\SensitiveParameter] array|KeyRing $keySet): string
    {
        $key = $this->resolve($kid, $keySet);

        return Base64Url::encode(hash_hmac(SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM, $payload, $key, true));
    }

    public function signWithKeyRing(string $payload, #[\SensitiveParameter] KeyRing $keyRing): string
    {
        $entry = $keyRing->activeForWrite(
            KeyPurpose::KEY_ROTATION,
            SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM,
        );

        return $this->sign($payload, $entry->id, $keyRing);
    }

    /**
     * @param array<string, string>|KeyRing $keySet
     */
    public function verify(
        string $payload,
        string $signature,
        #[\SensitiveParameter]
        array|KeyRing $keySet,
        ?string $kid = null,
    ): bool {
        return $this->verifyResult($payload, $signature, $keySet, $kid)->verified;
    }

    /**
     * @param array<string, string>|KeyRing $keySet
     */
    public function verifyResult(
        string $payload,
        string $signature,
        #[\SensitiveParameter]
        array|KeyRing $keySet,
        ?string $kid = null,
    ): KeyVerificationResult {
        if ($kid !== null) {
            $usedFallbackKey = false;
            if ($keySet instanceof KeyRing) {
                $entry = $keySet->resolveForVerification(
                    $kid,
                    KeyPurpose::KEY_ROTATION,
                    SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM,
                );
                $usedFallbackKey = $entry?->status === KeyStatus::FALLBACK;
            }
            $computed = Base64Url::encode(hash_hmac(SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM, $payload, $this->resolve($kid, $keySet), true));

            return new KeyVerificationResult(
                SecureCompare::equals($computed, $signature),
                $kid,
                $usedFallbackKey,
            );
        }

        foreach (KeyCandidates::orderedEntries(
            $keySet,
            'All rotation keys must be non-empty strings.',
            'At least one rotation key is required.',
            KeyPurpose::KEY_ROTATION,
            SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM,
        ) as $entry) {
            SecurityPolicy::assertHmacSecret($entry['key'], 'Key-rotation secret');
            $computed = Base64Url::encode(hash_hmac(SecurityPolicy::DEFAULT_KEY_ROTATION_HMAC_ALGORITHM, $payload, $entry['key'], true));
            if (SecureCompare::equals($computed, $signature)) {
                return new KeyVerificationResult(true, $entry['id'], !$entry['active']);
            }
        }

        return new KeyVerificationResult(false);
    }
}
