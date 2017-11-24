<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

trait ComputesSignature
{
	use HandlesSignature;

	protected function computeSignature($input, $secret)
	{
		return hash_hmac($this->signature_algorithm, $input, $secret, true);
	}
}
