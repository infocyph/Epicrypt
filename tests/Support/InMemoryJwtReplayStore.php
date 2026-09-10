<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Token\Jwt\JwtReplayStoreInterface;

final class InMemoryJwtReplayStore implements JwtReplayStoreInterface
{
    /** @var array<string, array<string, int>> */
    private array $consumed = [];

    public function consume(string $namespace, string $tokenId, int $expiresAt): bool
    {
        if (isset($this->consumed[$namespace][$tokenId])) {
            return false;
        }
        $this->consumed[$namespace][$tokenId] = $expiresAt;

        return true;
    }

    public function isRevoked(string $namespace, string $tokenId, int $expiresAt): bool
    {
        return ($this->consumed[$namespace][$tokenId] ?? null) === $expiresAt;
    }
}
