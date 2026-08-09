<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Token\Opaque\RefreshTokenRecord;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenGrant;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenRotationStatus;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenStoreInterface;

final class InMemoryRefreshTokenStore implements RefreshTokenStoreInterface
{
    /** @var array<string, array{record: RefreshTokenRecord, consumed: bool}> */
    private array $records = [];

    /** @var array<string, true> */
    private array $revokedFamilies = [];

    public function create(RefreshTokenRecord $record): bool
    {
        if (isset($this->records[$record->digest])) {
            return false;
        }
        $this->records[$record->digest] = ['record' => $record, 'consumed' => false];

        return true;
    }

    public function revokeFamily(string $tokenDigest, int $revokedAt): bool
    {
        if ($revokedAt < 1) {
            return false;
        }
        $entry = $this->records[$tokenDigest] ?? null;
        if ($entry === null) {
            return false;
        }
        $this->revokedFamilies[$entry['record']->familyId] = true;

        return true;
    }

    public function revokeGrant(string $grantId, int $revokedAt): int
    {
        if ($revokedAt < 1) {
            return 0;
        }
        $families = [];
        foreach ($this->records as $entry) {
            $record = $entry['record'];
            if ($record->grant->id === $grantId) {
                $families[$record->familyId] = true;
                $this->revokedFamilies[$record->familyId] = true;
            }
        }

        return count($families);
    }

    public function rotate(
        string $currentDigest,
        string $replacementDigest,
        string $clientId,
        ?string $dpopKeyThumbprint,
        ?array $requestedScopes,
        int $now,
        int $idleLifetimeSeconds,
    ): array {
        if (isset($this->records[$replacementDigest])) {
            return self::result(RefreshTokenRotationStatus::CONFLICT);
        }
        $entry = $this->records[$currentDigest] ?? null;
        if ($entry === null) {
            return self::result(RefreshTokenRotationStatus::INVALID);
        }
        $record = $entry['record'];
        if (isset($this->revokedFamilies[$record->familyId])) {
            return self::result(RefreshTokenRotationStatus::REVOKED);
        }
        if ($entry['consumed']) {
            $this->revokedFamilies[$record->familyId] = true;

            return self::result(RefreshTokenRotationStatus::REUSED);
        }
        if ($now >= $record->idleExpiresAt || $now >= $record->grant->expiresAt) {
            return self::result(RefreshTokenRotationStatus::EXPIRED);
        }
        if (!hash_equals($record->grant->clientId, $clientId)) {
            return self::result(RefreshTokenRotationStatus::CLIENT_MISMATCH);
        }
        if (!self::sameSender($record->grant->dpopKeyThumbprint, $dpopKeyThumbprint)) {
            return self::result(RefreshTokenRotationStatus::SENDER_MISMATCH);
        }
        $successorGrant = $record->grant;
        if ($requestedScopes !== null) {
            foreach ($requestedScopes as $scope) {
                if (!in_array($scope, $record->grant->scopes, true)) {
                    return self::result(RefreshTokenRotationStatus::SCOPE_MISMATCH);
                }
            }
            $successorGrant = new RefreshTokenGrant(
                $record->grant->id,
                $record->grant->subject,
                $record->grant->clientId,
                $record->grant->audiences,
                $requestedScopes,
                $record->grant->expiresAt,
                $record->grant->dpopKeyThumbprint,
            );
        }

        $this->records[$currentDigest]['consumed'] = true;
        $this->records[$replacementDigest] = [
            'record' => new RefreshTokenRecord(
                $replacementDigest,
                $record->familyId,
                $successorGrant,
                $now,
                min($record->grant->expiresAt, $now + $idleLifetimeSeconds),
            ),
            'consumed' => false,
        ];

        return ['status' => RefreshTokenRotationStatus::ROTATED, 'grant' => $successorGrant];
    }

    /** @return array{status: RefreshTokenRotationStatus, grant: null} */
    private static function result(RefreshTokenRotationStatus $status): array
    {
        return ['status' => $status, 'grant' => null];
    }

    private static function sameSender(?string $expected, ?string $actual): bool
    {
        if ($expected === null || $actual === null) {
            return $expected === $actual;
        }

        return hash_equals($expected, $actual);
    }
}
