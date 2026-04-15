<?php

namespace Infocyph\Epicrypt\Password\Secret;

use Infocyph\Epicrypt\Internal\Json;

final class SecureSecretSerializer
{
    /**
     * @param array<string, scalar|array<string, scalar>> $secret
     */
    public function serialize(array $secret): string
    {
        return Json::encode($secret);
    }

    /**
     * @return array<string, mixed>
     */
    public function unserialize(string $serialized): array
    {
        return Json::decodeToArray($serialized);
    }
}
