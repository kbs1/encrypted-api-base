<?php

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\Encryption\UnableToEncodeAsBase64Exception;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\Encryption\UnableToEncodeAsJsonException;

use Kbs1\EncryptedApiBase\Cryptography\Concerns\HandlesSharedSecrets;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithCipher;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\ComputesSignature;

/*
 * Class used to generate arbitrary (including invalid) input data for Decryptor
 */

class RequestGenerator
{
	use HandlesSharedSecrets, WorksWithCipher, ComputesSignature;

	public function __construct($secret1, $secret2)
	{
		$this->setSharedSecrets($secret1, $secret2);
	}

	public function generate($data, array $extra = [], $encode = true)
	{
		$iv = $this->generateRandomBytes($this->getIvLength());
		$encrypted = $this->encryptString($this->encodeJson($data), $iv, $this->secret1);
		$signature = $this->computeSignature(bin2hex($encrypted) . bin2hex($iv), $this->secret2);

		$result = $extra + ['data' => bin2hex($encrypted), 'iv' => bin2hex($iv), 'signature' => bin2hex($signature)];
		return $encode ? $this->encodeJson($result) : $result;
	}

	public function encodeBase64($value)
	{
		$result = base64_encode($value);
		if ($result === false)
			throw new UnableToEncodeAsBase64Exception();

		return $result;
	}

	public function jsonTransmittableValue($value)
	{
		if (!is_string($value))
			return $value;

		try {
			$this->ensureValidUtf8($value);
		} catch (UnsupportedVariableTypeException $ex) {
			return 'b' . $this->encodeBase64($value);
		}

		return 'u' . $value;
	}

	public function jsonTransmittableArray(array $array)
	{
		$result = [];

		foreach ($array as $key => $value)
			if (is_array($value))
				$result[$this->jsonTransmittableValue($key)] = $this->jsonTransmittableArray($value);
			else
				$result[$this->jsonTransmittableValue($key)] = $this->jsonTransmittableValue($value);

		return $result;
	}

	public function encodeJson($value)
	{
		$result = @json_encode($value, 0, 1024);
		if (json_last_error() !== JSON_ERROR_NONE)
			throw new UnableToEncodeAsJsonException(json_last_error_msg());

		return $result;
	}

	public function generateRandomBytes($length)
	{
		return str_repeat('a', $length);
	}
}
