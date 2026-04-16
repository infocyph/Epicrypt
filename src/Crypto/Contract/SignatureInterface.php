<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto\Contract;

interface SignatureInterface extends SignerInterface, VerifierInterface {}
