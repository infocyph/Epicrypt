<?php

namespace Infocyph\Epicrypt\Internal;

final class SecureCompare
{
    public static function equals(string $known, string $given): bool
    {
        return hash_equals($known, $given);
    }
}
