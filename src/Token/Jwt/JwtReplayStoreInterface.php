<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

interface JwtReplayStoreInterface
{
    public function consume(string $issuer, string $jwtId, int $expiresAt): bool;
}
