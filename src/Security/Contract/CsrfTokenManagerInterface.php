<?php

namespace Infocyph\Epicrypt\Security\Contract;

interface CsrfTokenManagerInterface
{
    public function issueToken(string $sessionId): string;

    public function verifyToken(string $sessionId, string $token): bool;
}
