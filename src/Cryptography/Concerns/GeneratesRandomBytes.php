<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\WeakRandomBytesException;

trait GeneratesRandomBytes
{
	protected function generateRandomBytes($length)
	{
		$bytes = openssl_random_pseudo_bytes($length, $is_strong);
		if (!$is_strong)
			throw new WeakRandomBytesException();

		return $bytes;
	}
}
