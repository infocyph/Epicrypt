<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRecord;
use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationStoreInterface;

final class InMemoryOAuthAuthorizationStore implements OAuthAuthorizationStoreInterface
{
    /** @var array<string, OAuthAuthorizationRecord> */
    private array $records = [];

    public function create(OAuthAuthorizationRecord $record): bool
    {
        if (isset($this->records[$record->authorizationId])) {
            return false;
        }
        $this->records[$record->authorizationId] = $record;

        return true;
    }

    public function find(string $authorizationId): ?OAuthAuthorizationRecord
    {
        return $this->records[$authorizationId] ?? null;
    }

    public function revoke(string $authorizationId, int $revokedAt): ?OAuthAuthorizationRecord
    {
        $record = $this->records[$authorizationId] ?? null;
        if (!$record instanceof OAuthAuthorizationRecord) {
            return null;
        }
        $record = $record->revoked($revokedAt);
        $this->records[$authorizationId] = $record;

        return $record;
    }
}
