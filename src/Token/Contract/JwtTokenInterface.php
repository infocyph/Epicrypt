<?php

namespace Infocyph\Epicrypt\Token\Contract;

interface JwtTokenInterface extends TokenEncoderInterface, TokenDecoderInterface, TokenVerifierInterface {}
