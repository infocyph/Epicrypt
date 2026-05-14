<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

/**
 * @internal
 */
final readonly class VersionedPayloadResult
{
    /**
     * @param list<string> $parts
     */
    public function __construct(
        public bool $versioned,
        public array $parts,
    ) {}
}
