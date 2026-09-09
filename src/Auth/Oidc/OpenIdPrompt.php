<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

enum OpenIdPrompt: string
{
    case NONE = 'none';
    case LOGIN = 'login';
    case CONSENT = 'consent';
    case SELECT_ACCOUNT = 'select_account';
}
