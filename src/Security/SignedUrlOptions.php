<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class SignedUrlOptions
{
    /**
     * @param array<int, mixed>|null $allowedHosts
     */
    public function __construct(
        public ?string $method = null,
        public bool $bindHost = true,
        public bool $bindScheme = true,
        public bool $allowAbsoluteUrls = true,
        public bool $allowRelativeUrls = false,
        public bool $allowArrayParameters = false,
        public ?array $allowedHosts = null,
    ) {
        if ($this->method !== null) {
            $this->method = strtoupper(trim($this->method));
            if ($this->method === '') {
                throw new ConfigurationException('Signed URL method binding must be a non-empty string when provided.');
            }
        }

        if ($this->allowedHosts !== null) {
            $normalizedHosts = [];
            foreach ($this->allowedHosts as $host) {
                if (!is_string($host)) {
                    throw new ConfigurationException('Signed URL allowedHosts must contain only non-empty strings.');
                }

                $normalized = strtolower(trim($host));
                if ($normalized === '') {
                    throw new ConfigurationException('Signed URL allowedHosts must contain only non-empty strings.');
                }

                $normalizedHosts[] = $normalized;
            }

            if ($normalizedHosts === []) {
                throw new ConfigurationException('Signed URL allowedHosts must not be empty when provided.');
            }

            $this->allowedHosts = array_values(array_unique($normalizedHosts));
        }
    }
}
