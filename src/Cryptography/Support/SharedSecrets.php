<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Support;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidSharedSecretException;

class SharedSecrets
{
	protected $secret1, $secret2;
	protected $minimum_length = 32;

	public function __construct($secret1, $secret2)
	{
		$this->setSharedSecrets($secret1, $secret2);
	}

	public function getSecret1()
	{
		return $this->secret1;
	}

	public function getSecret2()
	{
		return $this->secret2;
	}

	public function getMinimumLenth()
	{
		return $this->minimum_length;
	}

	protected function setSharedSecrets($secret1, $secret2)
	{
		if (is_array($secret1))
			$secret1 = $this->byteArrayToString($secret1);

		if (is_array($secret2))
			$secret2 = $this->byteArrayToString($secret2);

		$this->ensureSharedSecretsValidity($secret1, $secret2);

		$this->secret1 = substr($secret1, 0, $this->getMinimumLenth());
		$this->secret2 = substr($secret1, $this->getMinimumLenth()) . $secret2;
	}

	protected function ensureSharedSecretsValidity($secret1, $secret2)
	{
		if (!is_string($secret1) || !is_string($secret2))
			throw new InvalidSharedSecretException;

		if (strlen($secret1) < $this->getMinimumLenth() || strlen($secret2) < $this->getMinimumLenth())
			throw new InvalidSharedSecretException;

		if (hash_equals($secret1, $secret2))
			throw new InvalidSharedSecretException;

		if (substr($secret1, 0, $this->getMinimumLenth()) === substr($secret2, 0, $this->getMinimumLenth()))
			throw new InvalidSharedSecretException;

		if (strpos($secret1, $secret2) !== false || strpos($secret2, $secret1) !== false)
			throw new InvalidSharedSecretException;
	}

	protected function byteArrayToString(array $array)
	{
		$result = '';
		foreach ($array as $element) {
			if (!is_int($element) || $element < 0 || $element > 255)
				throw new InvalidSharedSecretException;

			$result .= chr($element);
		}

		return $result;
	}
}
