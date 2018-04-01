<?php

namespace Kbs1\EncryptedApiBase\Cryptography;

use Kbs1\EncryptedApiBase\Cryptography\Support\{Envelope, SharedSecrets, Timestamp};

class Decryptor
{
	protected $data, $secrets, $timestamp, $signature;

	public function __construct($data, $secret1, $secret2)
	{
		$this->secrets = new SharedSecrets($secret1, $secret2);
		$this->timestamp = new Timestamp;
		$this->data = $data;
	}

	public function getOriginal()
	{
		$envelope = new Envelope($this->secrets);
		$envelope->fromTransmit($this->data);

		$payload = $envelope->extractPayload();
		$this->verifyTimestamp($payload->getTimestamp());
		$this->signature = $envelope->getSignature();

		return $payload->getOriginal();
	}

	public function getSignature()
	{
		return $this->signature;
	}

	protected function verifyTimestamp($input)
	{
		if (!is_numeric($input) || $input < $this->timestamp->getCurrentTimestamp() - 10)
			throw new InvalidTimestampException;
	}
}
