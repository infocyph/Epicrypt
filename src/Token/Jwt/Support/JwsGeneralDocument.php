<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;

/** @internal General JSON JWS document validation boundary. */
final class JwsGeneralDocument
{
    /** @return array{signatures: non-empty-list<array<string, mixed>>, payload?: mixed} */
    public static function decode(#[\SensitiveParameter] string $jws): array
    {
        $document = JwtToken::decodeJsonObject(
            $jws,
            'general JWS JSON serialization',
            JosePolicy::MAX_COMPACT_TOKEN_BYTES,
            JosePolicy::MAX_DOCUMENT_MEMBERS,
        );
        $signatures = $document['signatures'] ?? null;
        if (!is_array($signatures) || $signatures === [] || !array_is_list($signatures)) {
            throw new ConfigurationException('General JWS must contain a non-empty signatures list.');
        }
        if (count($signatures) > JosePolicy::MAX_PARTICIPANTS) {
            throw new ConfigurationException('General JWS contains too many signatures.');
        }
        $normalized = [];
        foreach ($signatures as $signature) {
            if (!is_array($signature)) {
                throw new ConfigurationException('General JWS signatures must be objects.');
            }
            $normalized[] = self::stringKeyArray($signature);
        }
        if (array_key_exists('payload', $document)) {
            return ['signatures' => $normalized, 'payload' => $document['payload']];
        }

        return ['signatures' => $normalized];
    }

    /**
     * @param array<mixed, mixed> $input
     * @return array<string, mixed>
     */
    public static function stringKeyArray(array $input): array
    {
        $normalized = [];
        foreach ($input as $key => $value) {
            if (is_string($key)) {
                $normalized[$key] = $value;
            }
        }

        return $normalized;
    }

}
