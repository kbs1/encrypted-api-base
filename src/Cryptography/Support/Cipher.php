<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Support;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\{InvalidDataException, WeakRandomBytesException};

class Cipher
{
	protected $algorithm = 'aes-256-ctr';
	protected $iv_length;

	public function getIvLength()
	{
		return openssl_cipher_iv_length($this->algorithm);
	}

	public function encryptString($input, $iv, $secret)
	{
		$encrypted = @openssl_encrypt($input, $this->algorithm, $secret, OPENSSL_RAW_DATA, $iv);

		if ($encrypted === false)
			throw new InvalidDataException;

		return $encrypted;
	}

	public function decryptString($input, $iv, $secret)
	{
		$decrypted = @openssl_decrypt($input, $this->algorithm, $secret, OPENSSL_RAW_DATA, $iv);

		if ($decrypted === false)
			throw new InvalidDataException;

		return $decrypted;
	}

	public function generateRandomBytes($length)
	{
		$bytes = openssl_random_pseudo_bytes($length, $is_strong);
		if (!$is_strong)
			throw new WeakRandomBytesException;

		return $bytes;
	}
}
