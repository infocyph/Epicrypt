<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenRecord;
use Infocyph\Epicrypt\Auth\Personal\PersonalAccessTokenStoreInterface;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use InvalidArgumentException;

final class InMemoryPersonalAccessTokenStore implements PersonalAccessTokenStoreInterface
{
    /** @var array<string, PersonalAccessTokenRecord> */
    private array $records = [];

    public function __construct(private int $createConflictsRemaining = 0)
    {
        if ($this->createConflictsRemaining < 0) {
            throw new InvalidArgumentException('Personal-token conflict count cannot be negative.');
        }
    }

    public function create(PersonalAccessTokenRecord $record): bool
    {
        if ($this->createConflictsRemaining > 0) {
            $this->createConflictsRemaining--;
            return false;
        }
        if (isset($this->records[$record->tokenId])) {
            return false;
        }
        $this->records[$record->tokenId] = $record;

        return true;
    }

    public function find(string $tokenId): ?PersonalAccessTokenRecord
    {
        return $this->records[$tokenId] ?? null;
    }

    public function listForSubject(string $subject, int $limit = 100): array
    {
        if (!AuthProtocolPolicy::validText($subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES)
            || $limit < 1
            || $limit > AuthProtocolPolicy::MAX_STORE_LIST_RECORDS) {
            throw new ConfigurationException('Personal-access-token list query is outside supported bounds.');
        }

        $records = array_values(array_filter(
            $this->records,
            static fn(PersonalAccessTokenRecord $record): bool => $record->subject === $subject,
        ));
        usort(
            $records,
            static fn(PersonalAccessTokenRecord $a, PersonalAccessTokenRecord $b): int =>
                $b->createdAt <=> $a->createdAt ?: strcmp($a->tokenId, $b->tokenId),
        );

        return array_slice($records, 0, $limit);
    }

    public function revoke(string $tokenId, string $subject, int $revokedAt): ?PersonalAccessTokenRecord
    {
        $record = $this->records[$tokenId] ?? null;
        if (!$record instanceof PersonalAccessTokenRecord || $record->subject !== $subject) {
            return null;
        }
        $record = $record->revoked($revokedAt);
        $this->records[$tokenId] = $record;

        return $record;
    }

    public function revokeAll(string $subject, int $revokedAt): int
    {
        $revoked = 0;
        foreach ($this->records as $tokenId => $record) {
            if ($record->subject !== $subject || !$record->isActive($revokedAt)) {
                continue;
            }
            $this->records[$tokenId] = $record->revoked($revokedAt);
            $revoked++;
        }

        return $revoked;
    }
}
