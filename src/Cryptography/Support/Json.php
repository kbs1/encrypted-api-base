<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Support;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\{UnableToEncodeAsBase64Exception, UnableToEncodeAsJsonException,
	UnsupportedVariableTypeException, InvalidDataException};

class Json
{
	protected $validator;

	public function __construct()
	{
		$this->validator = new Validator;
	}

	public function encode($value)
	{
		$this->validator->ensureSupportedVariableTypes($value);

		if (is_array($value))
			$value = $this->safeArray($value);
		else
			$value = $this->safeValue($value);

		$result = @json_encode($value, 0, 513);
		if (json_last_error() !== JSON_ERROR_NONE)
			throw new UnableToEncodeAsJsonException(json_last_error_msg());

		return $result;
	}

	public function decode($input)
	{
		$result = @json_decode($input, true);

		if (json_last_error() !== JSON_ERROR_NONE)
			throw new InvalidDataException;

		if (is_array($result))
			$result = $this->originalArray($result);
		else
			$result = $this->originalValue($result);

		return $result;
	}

	public function decodeAndEnsureKeys($input, array $expected_keys)
	{
		$result = $this->decode($input);

		$keys = array_keys($result);
		sort($keys);
		sort($expected_keys);

		if ($keys !== $expected_keys)
			throw new InvalidDataException;

		return $result;
	}

	protected function safeValue($value)
	{
		if (!is_string($value))
			return $value;

		try {
			$this->validator->ensureValidUtf8($value);
		} catch (UnsupportedVariableTypeException $ex) {
			return 'b' . $this->encodeBase64($value);
		}

		return 'u' . $value;
	}

	protected function safeArray(array $array)
	{
		$result = [];

		foreach ($array as $key => $value)
			if (is_array($value))
				$result[$this->safeValue($key)] = $this->safeArray($value);
			else
				$result[$this->safeValue($key)] = $this->safeValue($value);

		return $result;
	}

	protected function originalValue($value)
	{
		if (!is_string($value))
			return $value;

		if (strlen($value) < 1)
			throw new InvalidDataException;

		if ($value[0] === 'u')
			return substr($value, 1);

		if ($value[0] === 'b')
			return $this->decodeBase64(substr($value, 1));

		throw new InvalidDataException;
	}

	protected function originalArray(array $array)
	{
		$result = [];

		foreach ($array as $key => $value)
			if (is_array($value))
				$result[$this->originalValue($key)] = $this->originalArray($value);
			else
				$result[$this->originalValue($key)] = $this->originalValue($value);

		return $result;
	}

	protected function encodeBase64($value)
	{
		$result = base64_encode($value);
		if ($result === false)
			throw new UnableToEncodeAsBase64Exception;

		return $result;
	}

	protected function decodeBase64($value)
	{
		$result = @base64_decode($value);
		if ($result === false)
			throw new InvalidDataException;

		return $result;
	}
}
