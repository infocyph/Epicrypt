<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

enum PersonalAccessTokenWildcardPolicy: string
{
    case DISABLED = 'disabled';

    case STAR = 'star';
}
