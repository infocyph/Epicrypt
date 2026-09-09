<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthClientType: string
{
    case PUBLIC = 'public';
    case CONFIDENTIAL = 'confidential';
}
