<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class KeyRing
{
    public const string STATUS_ACTIVE = 'active';

    public const string STATUS_DISABLED = 'disabled';

    public const string STATUS_FALLBACK = 'fallback';

    public const string STATUS_RETIRED = 'retired';

    /**
     * @var array<string, array{key: string, status: string, not_before: ?int, not_after: ?int, purpose: ?string}>
     */
    private array $keys;

    /**
     * @param array<string, string|array{key: string, status?: string, not_before?: int, not_after?: int, purpose?: string}> $keys
     */
    public function __construct(array $keys, private ?string $activeKeyId = null)
    {
        if ($keys === []) {
            throw new ConfigurationException('Key ring must contain at least one key.');
        }

        $normalized = [];
        foreach ($keys as $keyId => $entry) {
            if ($keyId === '') {
                throw new ConfigurationException('Key ring ids must be non-empty strings.');
            }

            $normalized[$keyId] = $this->normalizeEntry($keyId, $entry);
            if ($normalized[$keyId]['key'] === '') {
                throw new ConfigurationException(sprintf('Key ring entry "%s" must be a non-empty string.', $keyId));
            }
        }
        $this->keys = $normalized;

        if ($this->activeKeyId !== null && !array_key_exists($this->activeKeyId, $this->keys)) {
            throw new ConfigurationException('Active key id was not found in the key ring.');
        }

        if ($this->activeKeyId !== null && $this->keys[$this->activeKeyId]['status'] === self::STATUS_DISABLED) {
            throw new ConfigurationException('Active key id cannot point to a disabled key.');
        }
    }

    public function activeKey(): ?string
    {
        if ($this->activeKeyId === null) {
            return null;
        }

        $entry = $this->keys[$this->activeKeyId];
        if (!$this->isEntryUsable($entry)) {
            return null;
        }

        return $entry['key'];
    }

    public function activeKeyId(): ?string
    {
        return $this->activeKeyId;
    }

    /**
     * @return array<string, array{key: string, status: string, not_before: ?int, not_after: ?int, purpose: ?string}>
     */
    public function entries(): array
    {
        return $this->keys;
    }

    /**
     * @return array<string, string>
     */
    public function keys(): array
    {
        return array_map(
            static fn(array $entry): string => $entry['key'],
            $this->keys,
        );
    }

    /**
     * @return list<array{id: string, key: string, active: bool}>
     */
    public function orderedEntries(?string $purpose = null, ?int $at = null): array
    {
        $ordered = [];
        $now = $at ?? time();

        if ($this->activeKeyId !== null) {
            $activeEntry = $this->keys[$this->activeKeyId];
            if ($this->isEntryUsable($activeEntry, $purpose, $now)) {
                $ordered[] = [
                    'id' => $this->activeKeyId,
                    'key' => $activeEntry['key'],
                    'active' => true,
                ];
            }
        }

        foreach ($this->keys as $keyId => $entry) {
            if ($keyId === $this->activeKeyId) {
                continue;
            }

            if (!$this->isEntryUsable($entry, $purpose, $now)) {
                continue;
            }

            $ordered[] = [
                'id' => $keyId,
                'key' => $entry['key'],
                'active' => false,
            ];
        }

        return $ordered;
    }

    /**
     * @return list<string>
     */
    public function orderedKeys(): array
    {
        return array_column($this->orderedEntries(), 'key');
    }

    /**
     * @param array{key: string, status: string, not_before: ?int, not_after: ?int, purpose: ?string} $entry
     */
    private function isEntryUsable(array $entry, ?string $purpose = null, ?int $at = null): bool
    {
        if ($entry['status'] === self::STATUS_DISABLED) {
            return false;
        }

        if ($at !== null) {
            if ($entry['not_before'] !== null && $at < $entry['not_before']) {
                return false;
            }
            if ($entry['not_after'] !== null && $at > $entry['not_after']) {
                return false;
            }
        }

        if ($purpose !== null && $entry['purpose'] !== null && !hash_equals($entry['purpose'], $purpose)) {
            return false;
        }

        return true;
    }

    /**
     * @param string|array<string, mixed> $entry
     * @return array{key: string, status: string, not_before: ?int, not_after: ?int, purpose: ?string}
     */
    private function normalizeEntry(string $keyId, string|array $entry): array
    {
        if (is_string($entry)) {
            return $this->normalizeStringEntry($keyId, $entry);
        }

        $keyValue = $entry['key'] ?? null;
        if (!is_string($keyValue)) {
            throw new ConfigurationException(sprintf('Key ring entry "%s" must define a string "key".', $keyId));
        }
        $key = $keyValue;

        $status = $this->normalizeStatus(
            $this->stringOrDefaultStatus($entry['status'] ?? null, $keyId),
        );
        $notBefore = $this->nullableTimestamp($entry['not_before'] ?? null, $keyId, 'not_before');
        $notAfter = $this->nullableTimestamp($entry['not_after'] ?? null, $keyId, 'not_after');
        $purpose = $this->nullablePurpose($entry['purpose'] ?? null, $keyId);

        $this->validateWindow($notBefore, $notAfter, $keyId);

        return [
            'key' => $key,
            'status' => $status,
            'not_before' => $notBefore,
            'not_after' => $notAfter,
            'purpose' => $purpose,
        ];
    }

    private function normalizeStatus(string $status): string
    {
        $normalized = strtolower(trim($status));

        return match ($normalized) {
            self::STATUS_ACTIVE,
            self::STATUS_FALLBACK,
            self::STATUS_RETIRED,
            self::STATUS_DISABLED => $normalized,
            default => throw new ConfigurationException(sprintf('Unsupported key ring status "%s".', $status)),
        };
    }

    /**
     * @return array{key: string, status: string, not_before: ?int, not_after: ?int, purpose: ?string}
     */
    private function normalizeStringEntry(string $keyId, string $entry): array
    {
        return [
            'key' => $entry,
            'status' => $keyId === $this->activeKeyId ? self::STATUS_ACTIVE : self::STATUS_FALLBACK,
            'not_before' => null,
            'not_after' => null,
            'purpose' => null,
        ];
    }

    private function nullablePurpose(mixed $purpose, string $keyId): ?string
    {
        if ($purpose === null) {
            return null;
        }

        if (!is_string($purpose) || trim($purpose) === '') {
            throw new ConfigurationException(sprintf('Key ring entry "%s" purpose must be a non-empty string when provided.', $keyId));
        }

        return trim($purpose);
    }

    private function nullableTimestamp(mixed $value, string $keyId, string $label): ?int
    {
        if ($value === null) {
            return null;
        }

        if (!is_int($value)) {
            throw new ConfigurationException(sprintf('Key ring entry "%s" %s must be an integer unix timestamp.', $keyId, $label));
        }

        return $value;
    }

    private function stringOrDefaultStatus(mixed $status, string $keyId): string
    {
        if ($status === null) {
            return $keyId === $this->activeKeyId ? self::STATUS_ACTIVE : self::STATUS_FALLBACK;
        }

        if (!is_string($status)) {
            throw new ConfigurationException(sprintf('Key ring entry "%s" status must be a string.', $keyId));
        }

        return $status;
    }

    private function validateWindow(?int $notBefore, ?int $notAfter, string $keyId): void
    {
        if ($notBefore !== null && $notAfter !== null && $notAfter < $notBefore) {
            throw new ConfigurationException(sprintf('Key ring entry "%s" has invalid not_before/not_after bounds.', $keyId));
        }
    }
}
