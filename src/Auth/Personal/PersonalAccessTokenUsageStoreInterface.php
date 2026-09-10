<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

interface PersonalAccessTokenUsageStoreInterface
{
    public function lastUsedAt(string $tokenId, string $subject): ?int;

    /**
     * Atomically records usage no more often than the supplied interval.
     *
     * Implementations must key by exact token ID + subject and must not create
     * usage state for unknown tokens. The returned timestamp is the effective
     * persisted last-used value after the operation.
     */
    public function touch(
        string $tokenId,
        string $subject,
        int $usedAt,
        int $minimumIntervalSeconds,
    ): ?int;
}
