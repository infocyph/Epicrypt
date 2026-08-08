<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyStatus;

/**
 * @internal
 */
final class KeyCandidates
{
    /**
     * @param iterable<array-key, string>|KeyRing $keys
     * @return list<string>
     */
    public static function ordered(
        iterable|KeyRing $keys,
        string $emptyCandidateMessage,
        string $missingCandidateMessage,
        ?KeyPurpose $purpose = null,
        ?string $algorithm = null,
    ): array {
        return array_column(self::orderedEntries($keys, $emptyCandidateMessage, $missingCandidateMessage, $purpose, $algorithm), 'key');
    }

    /**
     * @param iterable<array-key, string>|KeyRing $keys
     * @return list<array{id: ?string, key: string, active: bool}>
     */
    public static function orderedEntries(
        iterable|KeyRing $keys,
        string $emptyCandidateMessage,
        string $missingCandidateMessage,
        ?KeyPurpose $purpose = null,
        ?string $algorithm = null,
    ): array {
        if ($keys instanceof KeyRing) {
            return self::fromKeyRing($keys, $purpose, $algorithm, $missingCandidateMessage);
        }

        $ordered = [];
        foreach ($keys as $keyId => $key) {
            if ($key === '') {
                throw new \InvalidArgumentException($emptyCandidateMessage);
            }

            $ordered[] = [
                'id' => is_string($keyId)
                    ? ($keyId !== '' ? $keyId : null)
                    : (string) $keyId,
                'key' => $key,
                'active' => false,
            ];
        }

        if ($ordered === []) {
            throw new \InvalidArgumentException($missingCandidateMessage);
        }

        return $ordered;
    }

    /** @return list<array{id: string, key: string, active: bool}> */
    private static function fromKeyRing(
        KeyRing $keys,
        ?KeyPurpose $purpose,
        ?string $algorithm,
        string $missingCandidateMessage,
    ): array {
        if ($purpose === null || $algorithm === null) {
            throw new \InvalidArgumentException('KeyRing candidates require an explicit purpose and algorithm.');
        }

        $ordered = [];
        foreach ($keys->readCandidates($purpose, $algorithm) as $entry) {
            $ordered[] = [
                'id' => $entry->id,
                'key' => $entry->key,
                'active' => $entry->status === KeyStatus::ACTIVE,
            ];
        }
        if ($ordered === []) {
            throw new \InvalidArgumentException($missingCandidateMessage);
        }

        return $ordered;
    }
}
