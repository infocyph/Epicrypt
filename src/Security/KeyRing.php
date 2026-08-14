<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;

final readonly class KeyRing
{
    /** @var array<string, KeyRingEntry> */
    private array $entries;

    /**
     * @param list<KeyRingEntry> $entries
     */
    public function __construct(#[\SensitiveParameter] array $entries, private ClockInterface $clock = new SystemClock())
    {
        if ($entries === []) {
            throw new ConfigurationException('Key ring must contain at least one entry.');
        }

        $indexed = [];
        foreach ($entries as $entry) {
            if (isset($indexed[$entry->id])) {
                throw new ConfigurationException(sprintf('Duplicate key id "%s".', $entry->id));
            }
            $indexed[$entry->id] = $entry;
        }
        $this->entries = $indexed;
    }

    public function activeForWrite(KeyPurpose $purpose, string $algorithm, ?string $issuer = null): KeyRingEntry
    {
        $matches = array_values(array_filter(
            $this->entries,
            fn(KeyRingEntry $entry): bool => $entry->status === KeyStatus::ACTIVE
                && $this->matches($entry, $purpose, $algorithm, $issuer),
        ));
        if (count($matches) !== 1) {
            throw new ConfigurationException('Exactly one eligible active key is required for this operation.');
        }

        return $matches[0];
    }

    /** @return list<KeyRingEntry> */
    public function readCandidates(
        KeyPurpose $purpose,
        string $algorithm,
        ?string $issuer = null,
    ): array {
        $active = [];
        $fallback = [];
        foreach ($this->entries as $entry) {
            if (!$this->matches($entry, $purpose, $algorithm, $issuer)) {
                continue;
            }
            if ($entry->status === KeyStatus::ACTIVE) {
                $active[] = $entry;
            } elseif ($entry->status === KeyStatus::FALLBACK) {
                $fallback[] = $entry;
            }
        }

        return [...$active, ...$fallback];
    }

    public function resolveForRead(
        string $id,
        KeyPurpose $purpose,
        string $algorithm,
        ?string $issuer = null,
    ): ?KeyRingEntry {
        return $this->resolve($id, $purpose, $algorithm, $issuer);
    }

    public function resolveForVerification(
        string $id,
        KeyPurpose $purpose,
        string $algorithm,
        ?string $issuer = null,
    ): ?KeyRingEntry {
        return $this->resolve($id, $purpose, $algorithm, $issuer);
    }

    private function matches(
        KeyRingEntry $entry,
        KeyPurpose $purpose,
        string $algorithm,
        ?string $issuer,
    ): bool {
        $now = $this->clock->now()->getTimestamp();
        if ($entry->purpose !== $purpose || !hash_equals($entry->algorithm, $algorithm)) {
            return false;
        }
        if ($entry->notBefore !== null && $now < $entry->notBefore) {
            return false;
        }
        if ($entry->notAfter !== null && $now >= $entry->notAfter) {
            return false;
        }

        return $issuer === null
            ? $entry->issuer === null
            : $entry->issuer !== null && hash_equals($entry->issuer, $issuer);
    }

    private function resolve(
        string $id,
        KeyPurpose $purpose,
        string $algorithm,
        ?string $issuer,
    ): ?KeyRingEntry {
        $entry = $this->entries[$id] ?? null;
        if ($entry === null || !in_array($entry->status, [KeyStatus::ACTIVE, KeyStatus::FALLBACK], true)) {
            return null;
        }

        return $this->matches($entry, $purpose, $algorithm, $issuer) ? $entry : null;
    }
}
