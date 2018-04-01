<?php

namespace Kbs1\EncryptedApiBase\Cryptography;

use Kbs1\EncryptedApiBase\Cryptography\Support\{Payload, SharedSecrets, Envelope};

class Encryptor
{
	protected $payload, $secrets, $signature;

	public function __construct(array $headers, $data, $secret1, $secret2, $provided_id = null, $url = null, $method = null, $uploads = null)
	{
		$this->payload = new Payload;
		$this->secrets = new SharedSecrets($secret1, $secret2);

		$this->payload->setHeaders($headers)->setData($data)->setId($provided_id)->setUrl($url)->setMethod($method)->setUploads($uploads);
	}

	public function getTransmit()
	{
		$envelope = new Envelope($this->secrets);
		$envelope->carryPayload($this->payload);
		$this->signature = $envelope->getSignature();

		return $envelope->getTransmit();
	}

	public function getId()
	{
		return $this->payload->getId();
	}

	public function getSignature()
	{
		return $this->signature;
	}
}
