<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenInspectionStatus;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenRecord;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenRotationStatus;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenStoreInterface;
use InvalidArgumentException;

final class InMemoryRefreshTokenStore implements RefreshTokenStoreInterface
{
    /** @var array<string, array{record: RefreshTokenRecord, consumed: bool}> */
    private array $records = [];

    /** @var array<string, true> */
    private array $revokedFamilies = [];

    public function __construct(
        private int $createConflictsRemaining = 0,
        private int $rotateConflictsRemaining = 0,
    ) {
        if ($this->createConflictsRemaining < 0 || $this->rotateConflictsRemaining < 0) {
            throw new InvalidArgumentException('Refresh-token conflict counts cannot be negative.');
        }
    }

    public function create(RefreshTokenRecord $record): bool
    {
        if ($this->createConflictsRemaining > 0) {
            $this->createConflictsRemaining--;
            return false;
        }
        if (isset($this->records[$record->tokenId])) {
            return false;
        }
        foreach ($this->records as $entry) {
            if ($entry['record']->familyId === $record->familyId) {
                return false;
            }
        }
        $this->records[$record->tokenId] = ['record' => $record, 'consumed' => false];

        return true;
    }

    public function inspect(RefreshTokenRecord $record, int $now): RefreshTokenInspectionStatus
    {
        $entry = $this->records[$record->tokenId] ?? null;
        if ($entry === null || !$entry['record']->sameState($record)) {
            return RefreshTokenInspectionStatus::INVALID;
        }
        $stored = $entry['record'];
        if (isset($this->revokedFamilies[$stored->familyId])) {
            return RefreshTokenInspectionStatus::REVOKED;
        }
        if ($entry['consumed']) {
            return RefreshTokenInspectionStatus::CONSUMED;
        }
        if ($now >= $stored->idleExpiresAt || $now >= $stored->grant->expiresAt) {
            return RefreshTokenInspectionStatus::EXPIRED;
        }

        return RefreshTokenInspectionStatus::ACTIVE;
    }

    public function revokeFamily(string $tokenId, int $revokedAt): bool
    {
        if ($revokedAt < 1 || !isset($this->records[$tokenId])) {
            return false;
        }
        $this->revokedFamilies[$this->records[$tokenId]['record']->familyId] = true;

        return true;
    }

    public function revokeAuthorization(string $authorizationId, int $revokedAt): int
    {
        if ($revokedAt < 1) {
            return 0;
        }
        $families = [];
        foreach ($this->records as $entry) {
            if ($entry['record']->grant->authorizationId === $authorizationId) {
                $families[$entry['record']->familyId] = true;
                $this->revokedFamilies[$entry['record']->familyId] = true;
            }
        }

        return count($families);
    }

    public function rotate(
        RefreshTokenRecord $current,
        RefreshTokenRecord $replacement,
        string $clientId,
        ?string $dpopKeyThumbprint,
        int $now,
    ): RefreshTokenRotationStatus {
        $entry = $this->records[$current->tokenId] ?? null;
        if ($entry === null || !$entry['record']->sameState($current)) {
            return RefreshTokenRotationStatus::INVALID;
        }
        $stored = $entry['record'];
        if (isset($this->revokedFamilies[$stored->familyId])) {
            return RefreshTokenRotationStatus::REVOKED;
        }
        if ($entry['consumed']) {
            $this->revokedFamilies[$stored->familyId] = true;
            return RefreshTokenRotationStatus::REUSED;
        }
        if ($now >= $stored->idleExpiresAt || $now >= $stored->grant->expiresAt) {
            return RefreshTokenRotationStatus::EXPIRED;
        }
        if (!hash_equals($stored->grant->clientId, $clientId)) {
            return RefreshTokenRotationStatus::CLIENT_MISMATCH;
        }
        if (!self::sameSender($stored->grant->dpopKeyThumbprint, $dpopKeyThumbprint)) {
            return RefreshTokenRotationStatus::SENDER_MISMATCH;
        }
        if ($replacement->familyId !== $stored->familyId
            || !$stored->grant->sameAuthorization($replacement->grant)
            || $replacement->issuedAt !== $now
            || $replacement->idleExpiresAt <= $now
            || $replacement->idleExpiresAt > $replacement->grant->expiresAt) {
            return RefreshTokenRotationStatus::INVALID;
        }
        if (!$stored->grant->scopesContain($replacement->grant)) {
            return RefreshTokenRotationStatus::SCOPE_MISMATCH;
        }
        if ($this->rotateConflictsRemaining > 0) {
            $this->rotateConflictsRemaining--;
            return RefreshTokenRotationStatus::CONFLICT;
        }
        if (isset($this->records[$replacement->tokenId])) {
            return RefreshTokenRotationStatus::CONFLICT;
        }

        $this->records[$current->tokenId]['consumed'] = true;
        $this->records[$replacement->tokenId] = ['record' => $replacement, 'consumed' => false];
        return RefreshTokenRotationStatus::ROTATED;
    }

    private static function sameSender(?string $expected, ?string $actual): bool
    {
        if ($expected === null || $actual === null) {
            return $expected === $actual;
        }
        return hash_equals($expected, $actual);
    }
}
