<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Support;

use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;

final class TokenKeyCandidates
{
    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<array{id: ?string, key: string, active: bool}>
     */
    public static function orderedEntries(
        iterable|KeyRing $keys,
        string $emptyCandidateMessage,
        string $missingCandidateMessage,
        ?KeyPurpose $purpose = null,
        ?string $algorithm = null,
    ): array {
        try {
            return KeyCandidates::orderedEntries($keys, $emptyCandidateMessage, $missingCandidateMessage, $purpose, $algorithm);
        } catch (\InvalidArgumentException $e) {
            throw new TokenException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<string>
     */
    public static function orderedKeys(
        iterable|KeyRing $keys,
        string $emptyCandidateMessage,
        string $missingCandidateMessage,
        ?KeyPurpose $purpose = null,
        ?string $algorithm = null,
    ): array {
        return array_column(self::orderedEntries($keys, $emptyCandidateMessage, $missingCandidateMessage, $purpose, $algorithm), 'key');
    }
}
