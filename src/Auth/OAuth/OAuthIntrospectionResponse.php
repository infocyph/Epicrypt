<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Throwable;

final readonly class OAuthIntrospectionResponse
{
    /** @var array<string, mixed> */
    public array $metadata;

    /** @param array<string, mixed> $metadata */
    private function __construct(public bool $active, array $metadata)
    {
        if (!$this->active && $metadata !== []) {
            throw new ConfigurationException('Inactive OAuth introspection responses must not expose token metadata.');
        }
        if (count($metadata) > AuthProtocolPolicy::MAX_AUTH_CLAIMS) {
            throw new ConfigurationException('OAuth introspection metadata exceeds the supported claim count.');
        }
        try {
            json_encode($metadata, JSON_THROW_ON_ERROR, AuthProtocolPolicy::MAX_JSON_DEPTH);
        } catch (Throwable $exception) {
            throw new ConfigurationException('OAuth introspection metadata must be bounded JSON data.', 0, $exception);
        }
        $this->metadata = $metadata;
    }

    public static function inactive(): self
    {
        return new self(false, []);
    }

    /** @param array<string, mixed> $metadata */
    public static function active(array $metadata): self
    {
        return new self(true, $metadata);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return ['active' => $this->active] + $this->metadata;
    }
}
