<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class JwtClaims
{
    private const array HEADER_NAMES = ['alg' => true, 'crit' => true, 'cty' => true, 'kid' => true, 'typ' => true];

    private const array REGISTERED = ['aud' => true, 'exp' => true, 'iat' => true, 'iss' => true, 'jti' => true, 'nbf' => true, 'sub' => true];

    /** @var array<string, mixed> */
    public array $custom;

    /**
     * @param list<string> $audiences
     * @param array<string, mixed> $custom
     */
    public function __construct(
        public string $issuer,
        public string $subject,
        public array $audiences,
        public int $expiresAt,
        public int $notBefore,
        public int $issuedAt,
        public string $jwtId,
        array $custom = [],
    ) {
        if ($this->issuer === '' || strlen($this->issuer) > 2048
            || $this->subject === '' || strlen($this->subject) > 255
            || $this->jwtId === '' || strlen($this->jwtId) > 128) {
            throw new ConfigurationException('JWT issuer, subject, and JWT ID must be non-empty.');
        }
        if ($this->audiences === []) {
            throw new ConfigurationException('JWT audiences must contain at least one value.');
        }
        foreach ($this->audiences as $audience) {
            if ($audience === '' || strlen($audience) > 2048) {
                throw new ConfigurationException('JWT audiences must contain non-empty strings.');
            }
        }
        if ($this->issuedAt > $this->notBefore || $this->notBefore >= $this->expiresAt) {
            throw new ConfigurationException('JWT timestamps must satisfy iat <= nbf < exp.');
        }
        $this->custom = self::normalizeCustomClaims($custom);
    }

    /**
     * @param list<string> $audiences
     * @param array<string, mixed> $custom
     */
    public static function issue(
        string $issuer,
        string $subject,
        array $audiences,
        int $ttlSeconds,
        array $custom = [],
        int $activationDelaySeconds = 0,
        ClockInterface $clock = new SystemClock(),
    ): self {
        if ($ttlSeconds < 1 || $activationDelaySeconds < 0 || $activationDelaySeconds >= $ttlSeconds) {
            throw new ConfigurationException('JWT TTL and activation delay must produce a positive active lifetime.');
        }

        $now = $clock->now()->getTimestamp();

        return new self(
            issuer: $issuer,
            subject: $subject,
            audiences: $audiences,
            expiresAt: $now + $ttlSeconds,
            notBefore: $now + $activationDelaySeconds,
            issuedAt: $now,
            jwtId: Base64Url::encode(random_bytes(24)),
            custom: $custom,
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'iss' => $this->issuer,
            'sub' => $this->subject,
            'aud' => $this->audiences,
            'exp' => $this->expiresAt,
            'nbf' => $this->notBefore,
            'iat' => $this->issuedAt,
            'jti' => $this->jwtId,
        ] + $this->custom;
    }

    /**
     * @param array<string, mixed> $custom
     * @return array<string, mixed>
     */
    private static function normalizeCustomClaims(array $custom): array
    {
        if (count($custom) > 57) {
            throw new ConfigurationException('JWT custom claim count exceeds the supported limit.');
        }

        foreach ($custom as $name => &$value) {
            if (isset(self::REGISTERED[$name]) || isset(self::HEADER_NAMES[$name])) {
                throw new ConfigurationException(sprintf('Custom claim "%s" is reserved.', $name));
            }
            $value = match ($name) {
                'scope' => implode(' ', self::normalizeStringList($value, 'scope')),
                'roles' => self::normalizeStringList($value, 'roles', false),
                'email' => is_string($value) && strlen($value) <= 254 && filter_var($value, FILTER_VALIDATE_EMAIL) !== false
                    ? $value
                    : throw new ConfigurationException('JWT email claim is invalid.'),
                'name', 'preferred_username' => is_string($value) && $value !== '' && strlen($value) <= 255
                    ? $value
                    : throw new ConfigurationException(sprintf('JWT %s claim is invalid.', $name)),
                default => self::validatedJsonValue($value),
            };
        }
        unset($value);

        return $custom;
    }

    /** @return list<string> */
    private static function normalizeStringList(mixed $value, string $name, bool $allowString = true): array
    {
        if ($allowString && is_string($value)) {
            $value = preg_split('/\s+/', trim($value), -1, PREG_SPLIT_NO_EMPTY);
        }
        if (!is_array($value) || $value === [] || !array_is_list($value)) {
            throw new ConfigurationException(sprintf('JWT %s claim must contain a non-empty string list.', $name));
        }

        $normalized = [];
        foreach ($value as $item) {
            if (!is_string($item) || $item === '' || strlen($item) > 255) {
                throw new ConfigurationException(sprintf('JWT %s claim contains an invalid value.', $name));
            }
            $normalized[] = $item;
        }

        return $normalized;
    }

    private static function validatedJsonValue(mixed $value): mixed
    {
        try {
            json_encode($value, JSON_THROW_ON_ERROR, 8);

            return $value;
        } catch (Throwable $exception) {
            throw new ConfigurationException('JWT custom claim is not a bounded JSON value.', 0, $exception);
        }
    }
}
