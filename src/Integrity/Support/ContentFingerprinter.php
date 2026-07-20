<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Integrity\Support;

use Infocyph\Epicrypt\Integrity\StringHasher;

/**
 * @internal
 */
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
        ksort($metadata, SORT_STRING);

        $canonical = 'EPICRYPT-CONTENT-FINGERPRINT-V1';
        $canonical .= self::encodeField($content);
        $canonical .= count($metadata) . ':';

        foreach ($metadata as $key => $value) {
            $canonical .= self::encodeField((string) $key);
            $canonical .= self::encodeScalar($value);
        }

        return $this->hasher->hash($canonical);
    }

    private static function encodeField(string $value): string
    {
        return strlen($value) . ':' . $value;
    }

    private static function encodeScalar(bool|float|int|string $value): string
    {
        return match (true) {
            is_bool($value) => 'b' . ($value ? '1' : '0'),
            is_float($value) => 'f' . self::encodeField(serialize($value)),
            is_int($value) => 'i' . self::encodeField((string) $value),
            default => 's' . self::encodeField($value),
        };
    }
}
