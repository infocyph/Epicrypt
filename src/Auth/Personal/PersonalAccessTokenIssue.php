<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

final readonly class PersonalAccessTokenIssue
{
    public function __construct(
        #[\SensitiveParameter]
        public string $token,
        public PersonalAccessTokenRecord $record,
    ) {}
}
