<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

enum OpenIdPrompt: string
{
    case CONSENT = 'consent';

    case LOGIN = 'login';

    case NONE = 'none';

    case SELECT_ACCOUNT = 'select_account';
}
