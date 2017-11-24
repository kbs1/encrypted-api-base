<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidSignatureException;

trait VerifiesSignature
{
	use ComputesSignature;

	protected function verifySignature($input, $expected_signature, $secret)
	{
		$signature = $this->computeSignature($input, $secret);

		if (!hash_equals($signature, $expected_signature))
			throw new InvalidSignatureException();
	}
}
