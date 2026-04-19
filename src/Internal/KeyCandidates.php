<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Security\KeyRing;

/**
 * @internal
 */
final class KeyCandidates
{
    /**
     * @param iterable<array-key, string>|KeyRing $keys
     * @return list<string>
     */
    public static function ordered(iterable|KeyRing $keys, string $emptyCandidateMessage, string $missingCandidateMessage): array
    {
        return array_column(self::orderedEntries($keys, $emptyCandidateMessage, $missingCandidateMessage), 'key');
    }

    /**
     * @param iterable<array-key, string>|KeyRing $keys
     * @return list<array{id: ?string, key: string, active: bool}>
     */
    public static function orderedEntries(iterable|KeyRing $keys, string $emptyCandidateMessage, string $missingCandidateMessage): array
    {
        if ($keys instanceof KeyRing) {
            return array_map(
                static fn(array $entry): array => ['id' => $entry['id'], 'key' => $entry['key'], 'active' => $entry['active']],
                $keys->orderedEntries(),
            );
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
}
