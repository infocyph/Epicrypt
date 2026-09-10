<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class KeyRingEntry
{
    public function __construct(
        public string $id,
        #[\SensitiveParameter]
        public string $key,
        public KeyStatus $status,
        public KeyPurpose $purpose,
        public string $algorithm,
        public ?int $notBefore = null,
        public ?int $notAfter = null,
        public ?string $issuer = null,
    ) {
        if (preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $this->id) !== 1) {
            throw new ConfigurationException('Key id must be a Base64URL-safe identifier.');
        }
        if ($this->key === '' || $this->algorithm === '') {
            throw new ConfigurationException('Key material and algorithm must be non-empty.');
        }
        if ($this->notBefore !== null && $this->notAfter !== null && $this->notBefore >= $this->notAfter) {
            throw new ConfigurationException('Key validity must satisfy notBefore < notAfter.');
        }
        if ($this->issuer !== null && $this->issuer === '') {
            throw new ConfigurationException('Key issuer must be non-empty when provided.');
        }
    }

    public function metadata(): KeyMetadata
    {
        return new KeyMetadata(
            $this->id,
            $this->status,
            $this->purpose,
            $this->algorithm,
            $this->notBefore,
            $this->notAfter,
            $this->issuer,
        );
    }
}
