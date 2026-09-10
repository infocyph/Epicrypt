<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenUsageStoreInterface;

final class InMemoryPersonalAccessTokenUsageStore implements PersonalAccessTokenUsageStoreInterface
{
    /** @var array<string, int> */
    private array $used = [];

    public int $writes = 0;

    public function touch(
        string $tokenId,
        string $subject,
        int $usedAt,
        int $minimumIntervalSeconds,
    ): ?int {
        $key = $this->key($tokenId, $subject);
        $previous = $this->used[$key] ?? null;
        if ($previous !== null && ($usedAt - $previous) < $minimumIntervalSeconds) {
            return $previous;
        }
        $this->used[$key] = $usedAt;
        $this->writes++;

        return $usedAt;
    }

    public function lastUsedAt(string $tokenId, string $subject): ?int
    {
        return $this->used[$this->key($tokenId, $subject)] ?? null;
    }

    private function key(string $tokenId, string $subject): string
    {
        return $subject . "\0" . $tokenId;
    }
}
