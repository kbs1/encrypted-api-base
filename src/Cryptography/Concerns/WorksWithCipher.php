<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidDataException;

trait WorksWithCipher
{
	protected $cipher_algorithm = 'aes-256-ctr';
	protected $iv_length;

	public function getIvLength()
	{
		return openssl_cipher_iv_length($this->cipher);
	}

	public function encryptString($input, $iv, $secret)
	{
		$encrypted = @openssl_encrypt($input, $this->cipher_algorithm, $secret, OPENSSL_RAW_DATA, $iv);

		if ($encrypted === false)
			throw new InvalidDataException();

		return $encrypted;
	}

	public function decryptString($input, $iv, $secret)
	{
		$decrypted = @openssl_decrypt($input, $this->cipher_algorithm, $secret, OPENSSL_RAW_DATA, $iv);

		if ($decrypted === false)
			throw new InvalidDataException();

		return $decrypted;
	}
}
