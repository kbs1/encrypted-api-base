<?php

namespace Kbs1\EncryptedApiBase\Cryptography;

use Kbs1\EncryptedApiBase\Exceptions\Encryption\UnableToEncodeAsBase64Exception;
use Kbs1\EncryptedApiBase\Exceptions\Encryption\UnableToEncodeAsJsonException;

use Kbs1\EncryptedApiBase\Cryptography\Concerns\EnsuresDataTypes;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\HandlesSharedSecrets;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithCipher;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\GeneratesRandomBytes;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithRequestId;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\ComputesSignature;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\ChecksBinHexFormat;

class Encryptor
{
	use EnsuresDataTypes, HandlesSharedSecrets, WorksWithCipher, GeneratesRandomBytes, WorksWithRequestId, ComputesSignature, ChecksBinHexFormat;

	protected $headers, $data, $force_id, $used_id, $url, $method;

	public function __construct(array $headers, $data, $secret1, $secret2, $force_id = null, $url = null, $method = null)
	{
		$this->ensureNoCircularReferences($headers);
		$this->ensureSupportedVariableTypes($headers);
		$this->ensureFlatArray($headers);

		$this->ensureStringOrArrayOrNull($data);

		if (is_array($data)) {
			$this->ensureNoCircularReferences($data);
			$this->ensureSupportedVariableTypes($data);
		}

		$this->ensureStringOrNull($force_id);
		$this->ensureStringOrNull($url);
		$this->ensureStringOrNull($method);

		$this->headers = $headers;
		$this->data = $data;

		if ($force_id)
			$this->checkBinHexFormat($force_id, $ths->getIdLength() * 2);

		$this->force_id = $force_id;

		$this->url = $url;
		$this->method = $method;

		$this->setSharedSecrets($secret1, $secret2);
	}

	public function encrypt()
	{
		$data = [
			'id' => $this->used_id = $this->force_id ?? bin2hex($this->generateRandomBytes($this->getIdLength())),
			'timestamp' => time(),
			'headers' => $this->encodeBase64Array($this->headers),
			'data' => $this->data === null ? null : (is_string($this->data) ? $this->encodeBase64($this->data) : $this->encodeBase64Array($this->data)),
			'url' => $this->encodeBase64($this->url),
			'method' => $this->encodeBase64(strtolower($this->method)),
		];

		$iv = $this->generateRandomBytes($this->getIvLength());
		$encrypted = $this->encryptString($this->encodeJson($data), $iv, $this->secret1);
		$signature = $this->computeSignature(bin2hex($encrypted) . bin2hex($iv), $this->secret2);

		return $this->encodeJson(['data' => bin2hex($encrypted), 'iv' => bin2hex($iv), 'signature' => bin2hex($signature)]);
	}

	public function getId()
	{
		return $this->used_id;
	}

	protected function encodeBase64($value)
	{
		$result = base64_encode($value);
		if ($value === false)
			throw new UnableToEncodeAsBase64Exception();

		return $value;
	}

	protected function encodeBase64Array(array $array)
	{
		$result = [];

		foreach ($array as $key => $value)
			if (is_array($value))
				$result[$this->encodeBase64($key)] = $this->encodeBase64Array($value);
			else
				$result[$this->encodeBase64($key)] = $this->encodeBase64($value);

		return $result;
	}

	protected function encodeJson($value)
	{
		$result = @json_encode($value);
		if (json_last_error() !== JSON_ERROR_NONE)
			throw new UnableToEncodeAsJsonException(json_last_error_msg());

		return $result;
	}
}
