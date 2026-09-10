<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use JsonException;
use Throwable;

/** @internal */
final class JwtToken
{
    public const int MAX_TOKEN_SIZE = JosePolicy::MAX_COMPACT_TOKEN_BYTES;

    /** @return array<string, mixed> */
    public static function decodeJsonObject(
        #[\SensitiveParameter]
        string $json,
        string $name,
        int $maximumBytes = JosePolicy::MAX_COMPACT_TOKEN_BYTES,
        int $maximumMembers = JosePolicy::MAX_DOCUMENT_MEMBERS,
    ): array {
        try {
            JosePolicy::assertInputSize($json, $maximumBytes, 'JOSE ' . $name);
            self::rejectDuplicateObjectKeys($json);
            $decoded = json_decode($json, true, JosePolicy::MAX_JSON_DEPTH, JSON_THROW_ON_ERROR);
            if (!is_array($decoded) || array_is_list($decoded)) {
                throw new JsonException('JOSE JSON payload must decode to an object.');
            }

            $result = [];
            foreach ($decoded as $key => $value) {
                if (!is_string($key)) {
                    throw new JsonException('JOSE JSON object keys must be strings.');
                }
                $result[$key] = $value;
            }
            JosePolicy::assertMemberCount($result, $maximumMembers, 'JOSE ' . $name);

            return $result;
        } catch (Throwable $exception) {
            throw new InvalidTokenException(sprintf('Invalid JWT %s.', $name), 0, $exception);
        }
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     * @return array{string, string}
     */
    public static function encodeSegments(array $header, #[\SensitiveParameter] array $payload): array
    {
        return [
            Base64Url::encode(Json::encode($header)),
            Base64Url::encode(Json::encode($payload)),
        ];
    }

    /**
     * @return array{string, string, string, array<string, mixed>, array<string, mixed>}
     */
    public static function parse(#[\SensitiveParameter] string $token): array
    {
        JosePolicy::assertInputSize($token, JosePolicy::MAX_COMPACT_TOKEN_BYTES, 'JWT');

        $parts = explode('.', $token);
        if (count($parts) !== 3 || in_array('', $parts, true)) {
            throw new InvalidTokenException('JWT must contain exactly three non-empty compact segments.');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $header = self::decodeSegment(
            $encodedHeader,
            'header',
            JosePolicy::MAX_HEADER_BYTES,
            JosePolicy::MAX_HEADER_MEMBERS,
        );
        $payload = self::decodeSegment(
            $encodedPayload,
            'payload',
            JosePolicy::MAX_COMPACT_TOKEN_BYTES,
            JosePolicy::MAX_CLAIM_MEMBERS,
        );
        $signature = Base64Url::decode($encodedSignature);
        if ($signature === '') {
            throw new InvalidTokenException('JWT signature must not be empty.');
        }

        return [$encodedHeader, $encodedPayload, $signature, $header, $payload];
    }

    /** @return array<string, mixed> */
    private static function decodeSegment(
        #[\SensitiveParameter]
        string $encodedSegment,
        string $name,
        int $maximumBytes,
        int $maximumMembers,
    ): array {
        try {
            return self::decodeJsonObject(
                Base64Url::decode($encodedSegment),
                $name,
                $maximumBytes,
                $maximumMembers,
            );
        } catch (Throwable $exception) {
            throw new InvalidTokenException(sprintf('Invalid JWT %s.', $name), 0, $exception);
        }
    }

    private static function findStringEnd(#[\SensitiveParameter] string $json, int $offset): int
    {
        $length = strlen($json);
        for (; $offset < $length; $offset++) {
            if ($json[$offset] === '\\') {
                $offset++;

                continue;
            }
            if ($json[$offset] === '"') {
                return $offset;
            }
        }

        throw new JsonException('Unterminated JSON string.');
    }

    private static function isObjectKey(#[\SensitiveParameter] string $json, int $offset, bool $insideObject): bool
    {
        $length = strlen($json);
        while ($offset < $length && ctype_space($json[$offset])) {
            $offset++;
        }

        return $insideObject && $offset < $length && $json[$offset] === ':';
    }

    private static function rejectDuplicateObjectKeys(#[\SensitiveParameter] string $json): void
    {
        /** @var list<array<string, true>> $objects */
        $objects = [];
        $length = strlen($json);
        for ($offset = 0; $offset < $length; $offset++) {
            if ($json[$offset] === '{') {
                $objects[] = [];

                continue;
            }
            if ($json[$offset] === '}') {
                array_pop($objects);

                continue;
            }
            if ($json[$offset] !== '"') {
                continue;
            }

            $start = $offset;
            $offset = self::findStringEnd($json, $offset + 1);
            if (!self::isObjectKey($json, $offset + 1, $objects !== [])) {
                continue;
            }

            $key = json_decode(substr($json, $start, ($offset - $start) + 1), true, 2, JSON_THROW_ON_ERROR);
            if (!is_string($key)) {
                throw new JsonException('JSON object key must be a string.');
            }
            $objectIndex = count($objects) - 1;
            if ($objectIndex < 0) {
                throw new JsonException('JSON object key is outside an object.');
            }
            $object = $objects[$objectIndex];
            if (isset($object[$key])) {
                throw new JsonException('Duplicate JSON object key.');
            }
            $object[$key] = true;
            $objects[$objectIndex] = $object;
        }
    }
}
