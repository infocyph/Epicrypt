<?php

namespace Infocyph\Epicrypt\Integrity\Support;

use Infocyph\Epicrypt\Integrity\String\StringHasher;

final readonly class ContentFingerprinter
{
    public function __construct(
        private StringHasher $hasher = new StringHasher('sha256'),
    ) {}

    /**
     * @param array<string, scalar> $metadata
     */
    public function fingerprint(string $content, array $metadata = []): string
    {
        ksort($metadata);
        $meta = [];
        foreach ($metadata as $key => $value) {
            $meta[] = $key . '=' . $value;
        }

        return $this->hasher->hash($content . '|' . implode('&', $meta));
    }
}
