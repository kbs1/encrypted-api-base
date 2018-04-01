<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Support;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidSignatureException;

class Signature
{
	protected $algorithm = 'sha512';
	protected $length = 64;

	public function getLength()
	{
		return $this->length;
	}

	public function verify($input, $expected_signature, $secret)
	{
		$signature = $this->compute($input, $secret);

		if (!hash_equals($signature, $expected_signature))
			throw new InvalidSignatureException;
	}

	public function compute($input, $secret)
	{
		return hash_hmac($this->algorithm, $input, $secret, true);
	}
}
