<?php

namespace Kbs1\EncryptedApiBase\Cryptography;

use Kbs1\EncryptedApiBase\Cryptography\Support\{Cipher, SharedSecrets};
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\{InvalidSharedSecretException, UnableToGenerateSharedSecretsException};

class SharedSecretsGenerator
{
	protected $cipher;
	protected $shared_secret_minimum_length = 32;

	public function __construct()
	{
		$this->cipher = new Cipher;
	}

	public function generateSharedSecrets()
	{
		$generated = false;
		$tries = 0;

		do {
			$tries++;

			$secret1 = $this->cipher->generateRandomBytes($this->shared_secret_minimum_length + rand(0, 32));
			$secret2 = $this->cipher->generateRandomBytes($this->shared_secret_minimum_length + rand(0, 32));

			try {
				new SharedSecrets($secret1, $secret2);
			} catch (InvalidSharedSecretException $ex) {
				continue;
			}

			$generated = true;
		} while (!$generated && $tries < 5000);

		if (!$generated)
			throw new UnableToGenerateSharedSecretsException;

		return ['secret1' => $this->stringToByteArray($secret1), 'secret2' => $this->stringToByteArray($secret2)];
	}

	protected function stringToByteArray($string)
	{
		return array_map('ord', str_split($string));
	}
}
