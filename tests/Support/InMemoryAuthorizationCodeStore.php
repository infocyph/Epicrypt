<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeConsumeStatus;
use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeRecord;
use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeStoreInterface;
use InvalidArgumentException;

final class InMemoryAuthorizationCodeStore implements AuthorizationCodeStoreInterface
{
    /** @var array<string, array{record: AuthorizationCodeRecord, consumed: bool}> */
    private array $records = [];

    public function __construct(private int $createConflictsRemaining = 0)
    {
        if ($this->createConflictsRemaining < 0) {
            throw new InvalidArgumentException('Authorization-code conflict count cannot be negative.');
        }
    }

    public function create(AuthorizationCodeRecord $record): bool
    {
        if ($this->createConflictsRemaining > 0) {
            $this->createConflictsRemaining--;
            return false;
        }
        if (isset($this->records[$record->codeId])) {
            return false;
        }

        $this->records[$record->codeId] = ['record' => $record, 'consumed' => false];
        return true;
    }

    public function consume(AuthorizationCodeRecord $record, int $now): AuthorizationCodeConsumeStatus
    {
        $entry = $this->records[$record->codeId] ?? null;
        if ($entry === null || !$entry['record']->sameState($record)) {
            return AuthorizationCodeConsumeStatus::INVALID;
        }
        if ($entry['consumed']) {
            return AuthorizationCodeConsumeStatus::REPLAYED;
        }
        if ($now >= $entry['record']->expiresAt) {
            return AuthorizationCodeConsumeStatus::EXPIRED;
        }

        $this->records[$record->codeId]['consumed'] = true;
        return AuthorizationCodeConsumeStatus::CONSUMED;
    }
}
