<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class PersonalAccessTokenPolicy
{
    public const int DEFAULT_LIFETIME_SECONDS = 2_592_000;

    public const int MAXIMUM_LIFETIME_SECONDS = 31_536_000;

    public function __construct(
        public string $audience,
        public int $defaultLifetimeSeconds = self::DEFAULT_LIFETIME_SECONDS,
        public int $maximumLifetimeSeconds = self::MAXIMUM_LIFETIME_SECONDS,
        public PersonalAccessTokenWildcardPolicy $wildcardPolicy = PersonalAccessTokenWildcardPolicy::DISABLED,
        public ?int $lastUsedWriteIntervalSeconds = null,
    ) {
        AuthProtocolPolicy::assertText(
            $this->audience,
            AuthProtocolPolicy::MAX_AUDIENCE_BYTES,
            'Personal-token audience',
        );
        if ($this->defaultLifetimeSeconds < 1
            || $this->maximumLifetimeSeconds < $this->defaultLifetimeSeconds
            || $this->maximumLifetimeSeconds > self::MAXIMUM_LIFETIME_SECONDS) {
            throw new ConfigurationException('Personal-token lifetime policy is invalid.');
        }
        if ($this->lastUsedWriteIntervalSeconds !== null
            && ($this->lastUsedWriteIntervalSeconds < 1 || $this->lastUsedWriteIntervalSeconds > 86_400)) {
            throw new ConfigurationException('Personal-token last-used write interval must be between 1 and 86400 seconds.');
        }
    }

    public function expiresAt(int $issuedAt, ?int $requestedExpiresAt = null): int
    {
        $expiresAt = $requestedExpiresAt ?? ($issuedAt + $this->defaultLifetimeSeconds);
        if ($expiresAt <= $issuedAt || ($expiresAt - $issuedAt) > $this->maximumLifetimeSeconds) {
            throw new ConfigurationException('Personal-token expiry exceeds the configured lifetime policy.');
        }

        return $expiresAt;
    }
}
