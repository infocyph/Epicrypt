<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Support;

use Infocyph\Epicrypt\Security\KeyVerificationResult;
use Throwable;

final class TokenAnyKey
{
    /**
     * @template TDecoded
     *
     * @param list<string> $keys
     * @param callable(string): TDecoded $decode
     * @param callable(?Throwable): Throwable $failure
     * @return TDecoded
     *
     * @throws Throwable
     */
    public static function decode(array $keys, callable $decode, callable $failure): mixed
    {
        $lastException = null;
        foreach ($keys as $key) {
            try {
                return $decode($key);
            } catch (Throwable $e) {
                $lastException = $e;
            }
        }

        throw $failure($lastException);
    }

    /**
     * @param list<array{id: ?string, key: string, active: bool}> $entries
     * @param callable(string): bool $verify
     */
    public static function verifyResult(array $entries, callable $verify): KeyVerificationResult
    {
        foreach ($entries as $entry) {
            if ($verify($entry['key'])) {
                return new KeyVerificationResult(true, $entry['id'], !$entry['active']);
            }
        }

        return new KeyVerificationResult(false);
    }
}
