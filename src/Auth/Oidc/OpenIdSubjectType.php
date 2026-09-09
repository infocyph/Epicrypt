<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

enum OpenIdSubjectType: string
{
    case PUBLIC = 'public';
    case PAIRWISE = 'pairwise';
}
