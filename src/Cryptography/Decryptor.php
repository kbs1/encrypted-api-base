<?php

namespace Kbs1\EncryptedApiBase\Cryptography;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidDataException;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\Decryption\InvalidTimestampException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\Decryption\UnableToDecodeBase64Exception;

use Kbs1\EncryptedApiBase\Cryptography\Concerns\EnsuresDataTypes;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\HandlesSharedSecrets;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithCipher;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithRequestId;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithTimestamp;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithUploadHashes;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\VerifiesSignature;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\ChecksBinHexFormat;

class Decryptor
{
	use EnsuresDataTypes, HandlesSharedSecrets, WorksWithCipher, WorksWithRequestId, WorksWithTimestamp, WorksWithUploadHashes, VerifiesSignature, ChecksBinHexFormat;

	protected $data;

	public function __construct($data, $secret1, $secret2)
	{
		$this->ensureString($data);
		$this->data = $data;

		$this->setSharedSecrets($secret1, $secret2);
	}

	public function decrypt()
	{
		$input = $this->parse();
		$this->verifySignature($input['data'] . $input['iv'], hex2bin($input['signature']), $this->secret2);

		$decrypted = $this->decryptData($input);

		$this->checkBinHexFormat($decrypted['id'], $this->getIdLength() * 2);
		$this->verifyTimestamp($decrypted['timestamp']);

		$original = $this->decode($decrypted);

		return $original;
	}

	protected function parse()
	{
		$input = $this->decodeAndCheckJson($this->data, ['signature', 'iv', 'data']);

		$this->checkBinHexFormat($input['signature'], $this->getSignatureLength());
		$this->checkBinHexFormat($input['iv'], $this->getIvLength());
		$this->checkBinHexFormat($input['data']);

		return $input;
	}

	protected function decryptData($input)
	{
		$decrypted = $this->decryptString(hex2bin($input['data']), hex2bin($input['iv']), $this->secret1);

		return $this->decodeAndCheckJson($decrypted, ['id', 'timestamp', 'headers', 'data', 'uploads', 'url', 'method']);
	}

	protected function verifyTimestamp($input)
	{
		if (!is_numeric($input) || $input < $this->getCurrentTimestamp() - 10)
			throw new InvalidTimestampException();
	}

	protected function decode(array $input)
	{
		$this->ensureHeadersArray($input['headers']);
		$this->ensureStringOrArray($input['data']);
		$this->ensureArrayOrNull($input['uploads']);
		$this->ensureStringOrNull($input['url']);
		$this->ensureStringOrNull($input['method']);

		if ($input['uploads']) {
			$this->ensureUploadsArray($input['uploads']);
			$this->checkArrayBinHexFormat($input['uploads'], $this->getUploadHashLength());
		}

		$input['headers'] = $this->decodeJsonTransmittableArray($input['headers']);

		if (is_array($input['data']))
			$input['data'] = $this->decodeJsonTransmittableArray($input['data']);
		if (is_string($input['data']))
			$input['data'] = $this->decodeJsonTransmittableValue($input['data']);

		$input['url'] = $this->decodeJsonTransmittableValue($input['url']);
		$input['method'] = $this->decodeJsonTransmittableValue($input['method']);

		return $input;
	}

	protected function decodeBase64($value)
	{
		$result = @base64_decode($value);
		if ($value === false)
			throw new UnableToDecodeBase64Exception();

		return $value;
	}

	protected function decodeJsonTransmittableValue($value)
	{
		if (!is_string($value))
			return $value;

		if (strlen($value) < 1)
			throw new InvalidDataException();

		if ($value[0] === 'u')
			return substr($value, 1);

		if ($value[0] === 'b')
			return $this->decodeBase64(substr($value, 1));

		throw new InvalidDataException();
	}

	protected function decodeJsonTransmittableArray(array $array)
	{
		$result = [];

		foreach ($array as $key => $value)
			if (is_array($value))
				$result[$this->decodeJsonTransmittableValue($key)] = $this->decodeJsonTransmittableArray($value);
			else
				$result[$this->decodeJsonTransmittableValue($key)] = $this->decodeJsonTransmittableValue($value);

		return $result;
	}

	protected function decodeAndCheckJson($input, array $expected_keys)
	{
		$result = @json_decode($input, true);

		if (json_last_error() !== JSON_ERROR_NONE)
			throw new InvalidDataException();

		$keys = array_keys($result);
		sort($keys);
		sort($expected_keys);

		if ($keys !== $expected_keys)
			throw new InvalidDataException();

		return $result;
	}
}
