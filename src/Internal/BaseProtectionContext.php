<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

/**
 * @internal
 */
abstract readonly class BaseProtectionContext
{
    public function __construct(
        public bool $keyIsBinary = false,
        public bool $nonceIsBinary = false,
        public string $aad = '',
        public ?string $keyId = null,
    ) {}
}
