<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

enum OpenIdSubjectType: string
{
    case PAIRWISE = 'pairwise';

    case PUBLIC = 'public';
}
