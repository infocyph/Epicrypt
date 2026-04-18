<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class KeyRing
{
    /**
     * @param array<string, string> $keys
     */
    public function __construct(
        private array $keys,
        private ?string $activeKeyId = null,
    ) {
        if ($this->keys === []) {
            throw new ConfigurationException('Key ring must contain at least one key.');
        }

        foreach ($this->keys as $keyId => $key) {
            if ($keyId === '') {
                throw new ConfigurationException('Key ring ids must be non-empty strings.');
            }

            if ($key === '') {
                throw new ConfigurationException(sprintf('Key ring entry "%s" must be a non-empty string.', $keyId));
            }
        }

        if ($this->activeKeyId !== null && !array_key_exists($this->activeKeyId, $this->keys)) {
            throw new ConfigurationException('Active key id was not found in the key ring.');
        }
    }

    public function activeKey(): ?string
    {
        return $this->activeKeyId === null ? null : $this->keys[$this->activeKeyId];
    }

    public function activeKeyId(): ?string
    {
        return $this->activeKeyId;
    }

    /**
     * @return array<string, string>
     */
    public function keys(): array
    {
        return $this->keys;
    }

    /**
     * @return list<array{id: string, key: string, active: bool}>
     */
    public function orderedEntries(): array
    {
        $ordered = [];

        if ($this->activeKeyId !== null) {
            $ordered[] = [
                'id' => $this->activeKeyId,
                'key' => $this->keys[$this->activeKeyId],
                'active' => true,
            ];
        }

        foreach ($this->keys as $keyId => $key) {
            if ($keyId === $this->activeKeyId) {
                continue;
            }

            $ordered[] = [
                'id' => $keyId,
                'key' => $key,
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
}
