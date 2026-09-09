<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class PersonalAccessTokenAbilities
{
    /** @var list<string> */
    public array $values;

    /** @param array<array-key, mixed> $abilities */
    public function __construct(
        array $abilities,
        public PersonalAccessTokenWildcardPolicy $wildcardPolicy = PersonalAccessTokenWildcardPolicy::DISABLED,
    ) {
        $normalized = AuthProtocolPolicy::normalizePersonalTokenAbilities($abilities);
        if ($this->wildcardPolicy === PersonalAccessTokenWildcardPolicy::DISABLED && in_array('*', $normalized, true)) {
            throw new ConfigurationException('Personal-token wildcard ability is disabled by policy.');
        }
        $this->values = $normalized;
    }

    public function allows(string $ability): bool
    {
        AuthProtocolPolicy::assertText(
            $ability,
            AuthProtocolPolicy::MAX_PERSONAL_TOKEN_ABILITY_BYTES,
            'Personal-token requested ability',
        );

        return in_array($ability, $this->values, true)
            || ($this->wildcardPolicy === PersonalAccessTokenWildcardPolicy::STAR
                && in_array('*', $this->values, true));
    }
}
