<?php

use Kbs1\EncryptedApiBase\Cryptography\Decryptor;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\UnsupportedVariableTypeException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidDataException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidSignatureException;

include_once __DIR__ . '/BaseTestCase.php';
include_once __DIR__ . '/RequestGenerator.php';

class DecryptorTest extends BaseTestCase
{
	protected $generator;

	/*
	 * Tested class
	 */

	protected function getClass()
	{
		return Decryptor::class;
	}

	protected function defaultConstructorArguments()
	{
		return [
			'data' => '{"data":"9c71adef9c981644c74a7a0241a02cccd6c3e0f5da483d47a90a402e0315336aa38b3a3df5af60d4b9bb62eda619ce5f5c06a69662a73ca12242cdf318937cc3661af420079eba44fe1805b3717a806bea477920f31b2ae5df3ccff4e60ef72e3196a48eaca97003482a60ffbc290d405e229007ce27a4e23b4c609a9313267ccc0ab1b8714d057905384d5108ebce4a5cba829f40ec475c9bd292106ad466d8acfc6460856a9aa88cdf0304d8dc669f5e3a5ca785f418ae95ef7c399bd957728056cf03a42c4e08dc9c34c5b9fe48e0fbc7ceeab13e20045aac19821e262cb44a6de3ff1efe7c503bd1991b2fef907f7263d6fbcc94cdb4b88dae6233e9affdaeee43a32d974190fe3536564606deb523be816f1adc29d13bfa7d52d70fe0e14ae3611bf271575174698f29f5a1e0861232713cdac79c7de2f6698d27f4396082a23fbd92cc896e242f1fbcb79ca90eed2171ffd9333a4b6f3a093918d32903c93989d444b89509d824d1faad86e1d76f1fe6b0584430f2bcbcd008ae9d5ab19d5cd9e8a194a832cd715513cf3e6f6d79b84f5e340813f5ca2efc834edcda","iv":"61616161616161616161616161616161","signature":"d391b05ace4cb6bda0cf062442a5b9beef1de3d3c42ba244080522ed4bd26198805731e7f4d84d0b4596ea6d105888a4e4b27d4e240809c806043f670ff14124"}',
			'secret1' => range(0, 31),
			'secret2' => range(40, 102, 2),
		];
	}

	protected function mockMethods()
	{
		return [
			'getCurrentTimestamp' => function () { return 1513694013; },
		];
	}

	/*
	 * GENERAL TESTS
	 */

	public function testConstructableWithValidArguments()
	{
		$this->expectsInstance();
	}

	public function testDecryption1()
	{
		$instance = $this->expectsMockInstance();

	}

	/*
	 * METHOD TESTS
	 */

	/*
	 * INPUT TESTS - invalid data
	 */

	public function testInvalidData1()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['data' => false]);
	}

	public function testInvalidData2()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['data' => null]);
	}

	public function testInvalidData3()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['data' => fopen('php://temp', 'r+')]);
	}

	public function testInvalidData4()
	{
		$instance = $this->expectsException(InvalidDataException::class, ['data' => 'invalidjson']);
		$instance->decrypt();
	}

	public function testInvalidData5()
	{
		$instance = $this->expectsException(InvalidDataException::class, ['data' => '{"data":"1","iv":"2","signature":"3"}']);
		$instance->decrypt();
	}

	public function testInvalidData6()
	{
		$instance = $this->expectsException(InvalidDataException::class, ['data' => '{"data":"ff","iv":"61","signature":"34"}']);
		$instance->decrypt();
	}

	/*
	 * INPUT TESTS - invalid signature
	 */

	public function testInvalidSignature1()
	{
		$data = $this->generator->generate($this->requestData(), ['signature' => str_repeat('a', 128)]);
		$instance = $this->expectsException(InvalidSignatureException::class, ['data' => $data]);
		$instance->decrypt();
	}

	public function testInvalidSignature2()
	{
		$data = $this->generator->generate($this->requestData(), ['signature' => str_repeat('a', 127)]);
		$instance = $this->expectsException(InvalidDataException::class, ['data' => $data]);
		$instance->decrypt();
	}

	/*
	 * INPUT TESTS - invalid iv
	 */

	public function testInvalidIv1()
	{
		$data = $this->generator->generate($this->requestData(), ['iv' => str_repeat('a', 31)]);
		$instance = $this->expectsException(InvalidDataException::class, ['data' => $data]);
		$instance->decrypt();
	}

	public function testInvalidIv2()
	{
		$data = $this->generator->generate($this->requestData(), ['iv' => str_repeat('a', 33)]);
		$instance = $this->expectsException(InvalidDataException::class, ['data' => $data]);
		$instance->decrypt();
	}

	/*
	 * INPUT TESTS - invalid keys
	 */

	public function testInvalidKeys1()
	{
		$data = $this->generator->generate($this->requestData(), ['extra' => 'value']);
		$instance = $this->expectsException(InvalidDataException::class, ['data' => $data]);
		$instance->decrypt();
	}

	/*
	 * INPUT TESTS - invalid timestamp
	 */

	public function testInvalidTimestamp1()
	{
		$data = $this->generator->generate($this->requestData(['timestamp' => 700]));
		$instance = $this->expectsException(InvalidDataException::class, ['data' => $data]);
		$instance->decrypt();
	}

	public function testInvalidTimestamp2()
	{
		$data = $this->generator->generate($this->requestData(['timestamp' => false]));
		$instance = $this->expectsException(InvalidDataException::class, ['data' => $data]);
		$instance->decrypt();
	}

	// TODO: should not fail
	public function testInvalidTimestamp3()
	{
		$data = $this->generator->generate($this->requestData([], []));
		$instance = $this->expectsException(InvalidDataException::class, ['data' => $data]);
		$instance->decrypt();
	}

	/*
	 * Helper methods
	 */

	protected function requestData(array $modify = [], array $unset = [])
	{
		$data = [
			'id' => '6161616161616161616161616161616161616161616161616161616161616161',
			'timestamp' => 1513694013,
			'headers' => [
				'X-Foo' => ['Bar'],
				'X-Baz' => ['Foo', 'Bar'],
			],
			'data' => 'string',
			'uploads' => ['a' => 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'],
			'url' => 'some/url',
			'method' => 'get',
		];

		$result = $modify + $data;

		foreach ($unset as $key)
			unset($result[$key]);

		return $result;
	}

	/*
	 * Fixtures
	 */

	public function setUp()
	{
		$this->generator = new RequestGenerator(range(0, 31), range(40, 102, 2));
	}

	public function tearDown()
	{
		$this->generator = null;
	}
}
