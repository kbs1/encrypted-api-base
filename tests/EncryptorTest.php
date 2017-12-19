<?php

use Kbs1\EncryptedApiBase\Cryptography\Encryptor;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\UnsupportedVariableTypeException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidArrayFormatException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\CircularReferencesException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidDataException;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\Encryption\UnableToEncodeAsJsonException;

include_once __DIR__ . '/BaseTestCase.php';

class EncryptorTest extends BaseTestCase
{
	/*
	 * Tested class
	 */

	protected function getClass()
	{
		return Encryptor::class;
	}

	protected function defaultConstructorArguments()
	{
		return [
			'headers' => [
				'X-Foo' => ['Bar'],
				'X-Baz' => ['Foo', 'Bar'],
			],
			'data' => 'string',
			'secret1' => range(0, 31),
			'secret2' => range(40, 102, 2),
			'force_id' => null,
			'url' => null,
			'method' => null,
			'uploads' => null,
		];
	}

	protected function mockMethods()
	{
		return [
			'generateRandomBytes' => function ($length) { return str_repeat('a', $length); },
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

	public function testEncryption1()
	{
		$instance = $this->expectsMockInstance();
		$this->assertEquals('{"data":"9c71adef9c981616931d2f5711f0789e8294b5a08a186915fd5d157b53456738f7dc6f68a5ff3486edec37b8f6499a0d0851f3c332f768f3761598a648c32891324da17557ceee44fe1805b3717a806bea477920f31b2ae5df3ccff4e60ef72e3196a48eaca97003482a60ffbc290d405e229007ce27a4e23b4c609a9313267ccc0ab1b8714d057905384d5108ebce4a5cba829f40ec475c9bd292106ad43f8faae93433c96fe1d3e4c032388ed758ab293d10fecbed56aedaae3e2a95861727de4cd85df4601f5f949c3d89f6fc51f1","iv":"61616161616161616161616161616161","signature":"9841f3ac1e1299b72b5322f44b2c2a30d9d0ea8ab4459e93591248c3a1c2eac98fa2bfdbb7497a4d4862c64daa5d24b20e0e9afb60e27038f980dcf051b55992"}', $instance->encrypt());
		$this->assertEquals('6161616161616161616161616161616161616161616161616161616161616161', $instance->getId());
	}

	public function testEncryption2()
	{
		$instance = $this->expectsMockInstance([
			'force_id' => 'deadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafe',
			'data' => ['a' => $this->invalidUtf8String(), 'b' => M_PI, M_PI => null, $this->invalidUtf8String() => $this->invalidUtf8String()],
			'uploads' => ['a' => 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'],
		]);

		$this->assertEquals('{"data":"9c71adef9c981644c74a7a0241a02cccd6c3e0f5da483d47a90a402e0315336aa38b3a3df5af60d4b9bb62eda619ce5f5c06a69662a73ca12242cdf318937cc3661af420079eba44fe1805b3717a806bea477920f31b2ae5df3ccff4e60ef72e3196a48eaca97003482a60ffbc290d405e229007ce27a4e23b4c609a9313267ccc0ab1b8714d057905384d5108ebce4a5cba829f40ec475c9bd292106ad466d8acfc6460856a9aa88cdf0304d8dc669f5e3a5ca785f418ae95ef7c399bd957728056cf03a42c4e08dc9c34c5b9fe48e0fbc7ceeab13e20045aac19821e262cb44a6de3ff1efe7c503bd1991b2fef907f7263d6fbcc94cdb4b88dae6233e9affdaeee43a32d974190fe3536564606deb523be816f1adc29d13bfa7d52d70fe0e14ae3611bf271575174698f29f5a1e0861232713cdac79c7de2f6698d27f4396082a23fbd92cc896e242f1fbcb79ca90eed2171ffd9333a4b6f3a093918d32903c93989d444b89509d824d1faad86e1d76f1fe6b0584430f2bcbcd008ae9d5ab19d5cd9e8a194a832cd715513cf3e6f6d79b84f5e340813f5ca2efc834edcda","iv":"61616161616161616161616161616161","signature":"d391b05ace4cb6bda0cf062442a5b9beef1de3d3c42ba244080522ed4bd26198805731e7f4d84d0b4596ea6d105888a4e4b27d4e240809c806043f670ff14124"}', $instance->encrypt());
		$this->assertEquals('deadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafe', $instance->getId());
	}

	/*
	 * METHOD TESTS
	 */

	public function testRequestDataAssembly1()
	{
		$method = $this->callableMethod('getRequestData');
		$result = $method->invoke($instance = $this->expectsMockInstance(['force_id' => 'deadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafe']));

		$expected = [
			'id' => 'deadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafe',
			'timestamp' => 1513694013,
			'headers' => ['uX-Foo' => [ 0 => 'uBar'], 'uX-Baz' => [0 => 'uFoo', 1 => 'uBar']],
			'data' => 'ustring',
			'uploads' => null,
			'url' => null,
			'method' => null,
		];

		$this->assertEquals($expected, $result);
		$this->assertEquals('deadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafe', $instance->getId());
	}

	public function testRequestDataAssembly2()
	{
		$method = $this->callableMethod('getRequestData');
		$result = $method->invoke($instance = $this->expectsMockInstance([
			'data' => ['a' => $this->invalidUtf8String(), 'b' => M_PI, M_PI => null, $this->invalidUtf8String() => $this->invalidUtf8String()],
			'uploads' => ['a' => 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'],
		]));

		$encoded_str = 'b' . base64_encode($this->invalidUtf8String());
		$expected = [
			'id' => '6161616161616161616161616161616161616161616161616161616161616161',
			'timestamp' => 1513694013,
			'headers' => ['uX-Foo' => [ 0 => 'uBar'], 'uX-Baz' => [0 => 'uFoo', 1 => 'uBar']],
			'data' => ['ua' => $encoded_str, 'ub' => M_PI, M_PI => null, $encoded_str => $encoded_str],
			'uploads' => ['a' => 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff'],
			'url' => null,
			'method' => null,
		];

		$this->assertEquals($expected, $result);
		$this->assertEquals('6161616161616161616161616161616161616161616161616161616161616161', $instance->getId());
	}

	/*
	 * INPUT TESTS - headers
	 */

	public function testInvalidHeadersData1()
	{
		$this->expectsException(InvalidArrayFormatException::class, ['headers' => ['X-Foo' => ['Bar', []]]]);
	}

	public function testInvalidHeadersData2()
	{
		$this->expectsException(InvalidArrayFormatException::class, ['headers' => ['X-Foo' => ['Bar', ['Baz', 'FooBar']], 'X-Baz' => ['Foo', 'Bar']]]);
	}

	public function testInvalidHeadersData3()
	{
		$this->expectsException(CircularReferencesException::class, ['headers' => $this->circularReferencedArray()]);
	}

	public function testInvalidHeadersData4()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['headers' => ['X-Foo' => [new stdClass(), 'Baz']]]);
	}

	public function testInvalidHeadersData5()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['headers' => ['X-Foo' => [fopen('php://temp', 'r+'), 'Baz']]]);
	}

	public function testInvalidHeadersData6()
	{
		$this->expectsException(InvalidArrayFormatException::class, ['headers' => ['X-Foo' => 'Bar']]);
	}

	public function testInvalidHeadersData7()
	{
		$this->expectsException(InvalidArrayFormatException::class, ['headers' => ['X-Foo', 'X-Bar']]);
	}

	public function testInvalidHeadersData8()
	{
		$this->expectsException(InvalidArrayFormatException::class, ['headers' => ['X-Foo' => ['key' => 'Value', 'Baz']]]);
	}

	/*
	 * INPUT TESTS - data
	 */

	public function testInvalidRequestData1()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['data' => new stdClass()]);
	}

	public function testInvalidRequestData2()
	{
		$this->expectsException(CircularReferencesException::class, ['data' => $this->circularReferencedArray()]);
	}

	public function testInvalidRequestData3()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['data' => [[['z'], fopen('php://temp', 'r+')], '7' => 8, M_PI]]);
	}

	public function testInvalidRequestData4()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['data' => [[['z'], new stdClass()], '7' => 8, M_PI]]);
	}

	public function testInvalidRequestData5()
	{
		$instance = $this->expectsException(UnableToEncodeAsJsonException::class, ['data' => $this->deepArray(513)]);
		$instance->encrypt();
	}

	public function testValidRequestData1()
	{
		$this->expectsInstance(['data' => null]);
	}

	public function testValidRequestData2()
	{
		$this->expectsInstance(['data' => $this->invalidUtf8String()]);
	}

	public function testValidRequestData3()
	{
		$this->expectsInstance(['data' => ['a' => $this->invalidUtf8String(), 'b' => ['c' => 'x', 'y']]]);
	}

	public function testValidRequestData4()
	{
		$instance = $this->expectsInstance(['data' => $this->deepArray(512)]);
		$this->assertStringStartsWith('{', $instance->encrypt());
	}

	/*
	 * INPUT TESTS - force_id
	 */

	public function testInvalidForceId1()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['force_id' => []]);
	}

	public function testInvalidForceId2()
	{
		$this->expectsException(InvalidDataException::class, ['force_id' => 'baz']);
	}

	public function testInvalidForceId3()
	{
		$this->expectsException(InvalidDataException::class, ['force_id' => 'badcafe']);
	}

	public function testValidForceId1()
	{
		$this->expectsInstance(['force_id' => 'badcafe0badcafe0badcafe0badcafe0badcafe0badcafe0badcafe0badcafe0']);
	}

	/*
	 * INPUT TESTS - url
	 */

	public function testInvalidUrl1()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['url' => []]);
	}

	public function testInvalidUrl2()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['url' => new stdClass()]);
	}

	public function testValidUrl1()
	{
		$this->expectsInstance(['url' => 'http://service.local?foo[]=bar']);
	}

	public function testValidUrl2()
	{
		$this->expectsInstance(['url' => 'local/foo']);
	}

	/*
	 * INPUT TESTS - method
	 */

	public function testInvalidMethod1()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['method' => []]);
	}

	public function testInvalidMethod2()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['method' => new stdClass()]);
	}

	public function testValidMethod1()
	{
		$this->expectsInstance(['method' => 'GET']);
	}

	public function testValidMethod2()
	{
		$this->expectsInstance(['method' => 'post']);
	}

	public function testValidMethod3()
	{
		$this->expectsInstance(['method' => 'poSt']);
	}

	/*
	 * INPUT TESTS - uploads
	 */

	public function testInvalidUploads1()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['uploads' => 'string']);
	}

	public function testInvalidUploads2()
	{
		$this->expectsException(UnsupportedVariableTypeException::class, ['uploads' => new stdClass()]);
	}

	public function testInvalidUploads3()
	{
		$this->expectsException(InvalidDataException::class, ['uploads' => ['a' => 'b', 'c' => 'd']]);
	}

	public function testInvalidUploads4()
	{
		$this->expectsException(InvalidArrayFormatException::class, ['uploads' => ['a' => 'b', 'c' => ['d', 'e' => 'f']]]);
	}

	public function testValidUploads1()
	{
		$this->expectsInstance(['uploads' => []]);
	}

	public function testValidUploads2()
	{
		$this->expectsInstance(['uploads' => ['a' => 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff', 'b' => 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff']]);
	}
}
