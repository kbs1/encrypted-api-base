<?php

namespace Kbs1\EncryptedApi\Cryptography;

use Kbs1\EncryptedApi\Exceptions\Base\InvalidDataException;
use Kbs1\EncryptedApi\Exceptions\Base\InvalidIvException;
use Kbs1\EncryptedApi\Exceptions\Base\InvalidSignatureException;
use Kbs1\EncryptedApi\Exceptions\Base\InvalidIdException;
use Kbs1\EncryptedApi\Exceptions\Base\InvalidSharedSecretException;
use Kbs1\EncryptedApi\Exceptions\Base\UnsupportedVariableTypeException;

class Base
{
	protected $secret1, $secret2;

	protected $data_algorithm = 'aes-256-ctr';
	protected $signature_algorithm = 'sha512';
	protected $signature_length = 64;
	protected $iv_length;
	protected $id_length = 32;
	protected $shared_secret_minimum_length = 32;

	public function __construct($secret1, $secret2)
	{
		if (is_array($secret1))
			$secret1 = $this->byteArrayToString($secret1);

		if (is_array($secret2))
			$secret1 = $this->byteArrayToString($secret2);

		$this->ensureString($secret1);
		$this->ensureString($secret2);

		$this->secret1 = $secret1;
		$this->secret2 = $secret2;
		$this->iv_length = openssl_cipher_iv_length($this->data_algorithm);
	}

	public function getSecret1()
	{
		$this->checkSharedSecretFormat($this->secret1);
		$this->checkSharedSecretsAreNotEqual();
		return substr($this->secret1, 0, $this->shared_secret_minimum_length);
	}

	public function getSecret2()
	{
		$this->checkSharedSecretFormat($this->secret2);
		$this->checkSharedSecretsAreNotEqual();
		return substr($this->secret1, $this->shared_secret_minimum_length) . $this->secret2;
	}

	protected function byteArrayToString(array $array)
	{
		$result = '';
		foreach ($array as $element) {
			if (!is_int($element) || $element < 0 || $element > 255)
				throw new InvalidSharedSecretException();

			$result .= chr($element);
		}

		return $result;
	}

	protected function ensureString($value)
	{
		if (!is_string($value))
			throw new UnsupportedVariableTypeException();
	}

	protected function getIvLengthInHexNotation()
	{
		return $this->iv_length * 2;
	}

	protected function getSignatureLengthInHexNotation()
	{
		return $this->signature_length * 2;
	}

	protected function getIdLengthInHexNotation()
	{
		return $this->id_length * 2;
	}

	protected function checkDataFormat($data)
	{
		if (!$this->checkBinHexFormat($data))
			throw new InvalidDataException();
	}

	protected function checkIvFormat($iv)
	{
		if (!$this->checkBinHexFormat($iv, $this->getIvLengthInHexNotation()))
			throw new InvalidIvException();
	}

	protected function checkSignatureFormat($signature)
	{
		if (!$this->checkBinHexFormat($signature, $this->getSignatureLengthInHexNotation()))
			throw new InvalidSignatureException();
	}

	protected function checkIdFormat($id)
	{
		if (!$this->checkBinHexFormat($id, $this->getIdLengthInHexNotation()))
			throw new InvalidIdException();
	}

	protected function checkSharedSecretFormat($secret)
	{
		 if (strlen($secret) < $this->shared_secret_minimum_length)
			throw new InvalidSharedSecretException();
	}

	protected function checkSharedSecretsAreNotEqual()
	{
		if (hash_equals($this->secret1, $this->secret2))
			throw new InvalidSharedSecretException();

		if (substr($this->secret1, 0, $this->shared_secret_minimum_length) === substr($this->secret2, 0, $this->shared_secret_minimum_length))
			throw new InvalidSharedSecretException();
	}

	protected function checkBinHexFormat($value, $length = null)
	{
		return preg_match('/^[\da-f]' . ($length ? '{' . $length . '}' : '+') . '$/siu', $value);
	}
}
