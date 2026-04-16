<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use Throwable;

/**
 * @internal
 */
final class JwtToken
{
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
        $parts = explode('.', $token, 3);
        if (count($parts) !== 3 || in_array('', $parts, true)) {
            throw new InvalidTokenException('Invalid JWT string/segment.');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $header = self::decodeSegment($encodedHeader, 'header');
        $payload = self::decodeSegment($encodedPayload, 'payload');
        $signature = Base64Url::decode($encodedSignature);

        if ($signature === '') {
            throw new InvalidTokenException('Invalid signature.');
        }

        return [$encodedHeader, $encodedPayload, $signature, $header, $payload];
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeSegment(string $encodedSegment, string $name): array
    {
        try {
            return Json::decodeToArray(Base64Url::decode($encodedSegment));
        } catch (Throwable $e) {
            throw new InvalidTokenException(sprintf('Invalid JWT %s.', $name), 0, $e);
        }
    }
}
