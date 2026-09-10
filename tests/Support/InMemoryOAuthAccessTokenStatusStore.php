<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\OAuth\OAuthAccessTokenStatusRecord;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAccessTokenStatusStoreInterface;

final class InMemoryOAuthAccessTokenStatusStore implements OAuthAccessTokenStatusStoreInterface
{
    /** @var array<string, OAuthAccessTokenStatusRecord> */
    private array $records = [];

    public function create(OAuthAccessTokenStatusRecord $record): bool
    {
        $key = self::key($record->issuer, $record->tokenId);
        if (isset($this->records[$key])) {
            return false;
        }
        $this->records[$key] = $record;

        return true;
    }

    public function find(string $issuer, string $tokenId): ?OAuthAccessTokenStatusRecord
    {
        return $this->records[self::key($issuer, $tokenId)] ?? null;
    }

    public function revoke(string $issuer, string $tokenId, int $revokedAt): ?OAuthAccessTokenStatusRecord
    {
        $key = self::key($issuer, $tokenId);
        $record = $this->records[$key] ?? null;
        if (!$record instanceof OAuthAccessTokenStatusRecord) {
            return null;
        }
        $record = $record->revoked($revokedAt);
        $this->records[$key] = $record;

        return $record;
    }

    private static function key(string $issuer, string $tokenId): string
    {
        return $issuer . "\0" . $tokenId;
    }
}
