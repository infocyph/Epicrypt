<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security\Enum;

enum SecurityTokenPurpose: string
{
    case ACTION_TOKEN = 'action_token';
    case CSRF = 'csrf';
    case EMAIL_VERIFICATION = 'email_verification';
    case PASSWORD_RESET = 'password_reset';
    case REMEMBER_TOKEN = 'remember_token';
}
