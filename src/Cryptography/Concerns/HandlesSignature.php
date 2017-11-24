<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

trait HandlesSignature
{
	protected $signature_algorithm = 'sha512';
	protected $signature_length = 32;

	protected function getSignatureLength()
	{
		return $this->signature_length;
	}
}
