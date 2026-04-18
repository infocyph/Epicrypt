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
     * @param iterable<string, string>|KeyRing $keys
     * @return list<string>
     */
    public static function ordered(iterable|KeyRing $keys, string $emptyCandidateMessage, string $missingCandidateMessage): array
    {
        if ($keys instanceof KeyRing) {
            return $keys->orderedKeys();
        }

        $ordered = [];
        foreach ($keys as $key) {
            if ($key === '') {
                throw new \InvalidArgumentException($emptyCandidateMessage);
            }

            $ordered[] = $key;
        }

        if ($ordered === []) {
            throw new \InvalidArgumentException($missingCandidateMessage);
        }

        return $ordered;
    }
}
