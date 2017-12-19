<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidUploadHashException;

trait WorksWithUploadHashes
{
	protected $upload_hash_algorithm = 'sha512';
	protected $upload_hash_length = 64;

	protected function getUploadHashLength()
	{
		return $this->upload_hash_length;
	}
}
