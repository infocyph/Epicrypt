<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Exception;

use Infocyph\Epicrypt\Security\SigningKeyReadinessFailureReason;

final class SigningKeyReadinessException extends ConfigurationException
{
    public function __construct(public readonly SigningKeyReadinessFailureReason $reason)
    {
        parent::__construct($reason->message());
    }
}
