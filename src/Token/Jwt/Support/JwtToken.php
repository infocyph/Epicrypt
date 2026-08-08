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
    public const int MAX_TOKEN_SIZE = 16 * 1024;

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $payload
     * @return array{string, string}
     */
    public static function encodeSegments(array $header, array $payload): array
    {
        return [
            Base64Url::encode(Json::encode($header)),
            Base64Url::encode(Json::encode($payload)),
        ];
    }

    /**
     * @return array{string, string, string, array<string, mixed>, array<string, mixed>}
     */
    public static function parse(string $token): array
    {
        if ($token === '' || strlen($token) > self::MAX_TOKEN_SIZE) {
            throw new InvalidTokenException('JWT size is invalid.');
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3 || in_array('', $parts, true)) {
            throw new InvalidTokenException('JWT must contain exactly three non-empty compact segments.');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;
        $header = self::decodeSegment($encodedHeader, 'header');
        $payload = self::decodeSegment($encodedPayload, 'payload');
        $signature = Base64Url::decode($encodedSignature);
        if ($signature === '') {
            throw new InvalidTokenException('JWT signature must not be empty.');
        }

        return [$encodedHeader, $encodedPayload, $signature, $header, $payload];
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeSegment(string $encodedSegment, string $name): array
    {
        try {
            $json = Base64Url::decode($encodedSegment);
            self::rejectDuplicateObjectKeys($json);

            return Json::decodeToArray($json);
        } catch (Throwable $exception) {
            throw new InvalidTokenException(sprintf('Invalid JWT %s.', $name), 0, $exception);
        }
    }

    private static function findStringEnd(string $json, int $offset): int
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

    private static function isObjectKey(string $json, int $offset, bool $insideObject): bool
    {
        $length = strlen($json);
        while ($offset < $length && ctype_space($json[$offset])) {
            $offset++;
        }

        return $insideObject && $offset < $length && $json[$offset] === ':';
    }

    private static function rejectDuplicateObjectKeys(string $json): void
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
            $object = array_pop($objects);
            if ($object === null) {
                throw new JsonException('JSON object key is outside an object.');
            }
            if (isset($object[$key])) {
                throw new JsonException('Duplicate JSON object key.');
            }
            $object[$key] = true;
            $objects[] = $object;
        }
    }
}
