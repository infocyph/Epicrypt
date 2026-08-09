<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class KeyDerivationContext
{
    public function __construct(
        public bool $saltIsBinary = false,
        public bool $asBase64Url = true,
        public bool $inputKeyMaterialIsBinary = false,
        public bool $rootKeyIsBinary = false,
        public ?int $opslimit = null,
        public ?int $memlimit = null,
        public string $algorithm = 'sha256',
        public string $info = '',
        public string $sodiumContext = 'EPCKDF01',
        public ?string $salt = null,
    ) {
        if ($this->opslimit !== null && $this->opslimit < 1) {
            throw new ConfigurationException('Password derivation operation limit must be positive.');
        }
        if ($this->memlimit !== null && $this->memlimit < 1) {
            throw new ConfigurationException('Password derivation memory limit must be positive.');
        }
    }
}
