<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class ProtectionOptions
{
    public function __construct(
        public string $purpose,
        public string $additionalAuthenticatedData = '',
        public ?string $keyId = null,
    ) {
        if ($this->purpose === '' || strlen($this->purpose) > 255) {
            throw new ConfigurationException('Protection purpose must contain between 1 and 255 bytes.');
        }

        if (str_contains($this->purpose, "\0")) {
            throw new ConfigurationException('Protection purpose must not contain NUL bytes.');
        }

        if (strlen($this->additionalAuthenticatedData) > 16 * 1024) {
            throw new ConfigurationException('Additional authenticated data must not exceed 16 KiB.');
        }

        if ($this->keyId !== null && !preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $this->keyId)) {
            throw new ConfigurationException('Protection key id must be a 1-128 character Base64URL-safe identifier.');
        }
    }
}
