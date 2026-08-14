<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

interface JwtReplayStoreInterface
{
    public function consume(string $namespace, string $tokenId, int $expiresAt): bool;

    public function isRevoked(string $namespace, string $tokenId, int $expiresAt): bool;
}
