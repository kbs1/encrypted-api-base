<?php

use PHPUnit\Framework\TestCase;

use Kbs1\EncryptedApiBase\Cryptography\Encryptor;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\UnsupportedVariableTypeException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidArrayFormatException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\CircularReferencesException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidSharedSecretException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidDataException;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\Encryption\UnableToEncodeAsJsonException;

class EncryptorTest extends TestCase
{
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
		$this->assertEquals('{"data":"9c71adef9c981616931d2f5711f0789e8294b5a08a186915fd5d157b53456738f7dc6f68a5ff3486edec37b8f6499a0d0851f3c332f768f3761598a648c32891324da17557ceee44fe1805b3717a806bea477920f31b2ae5df3ccff4e60ef72e3196a48eaca97003482a60ffbc290d405e229007ce27a4e23b4c609a9313267ccc0ab1b8714d057905384d5108ebce4a5cba829f40ec475c9bd292106ad43f8faae93433c96fe1d3e4c03038c38c52ad676b52a9cae40ee4c0b87032c19d0e27cf","iv":"61616161616161616161616161616161","signature":"624452a35acdb09ca3342bd18d1774dbc7b44b80d23928985c7f9d3ca07f7dd5b70c31bf0f3ce7ad3a102d95cb9223b983cc0f16706c831c24ce1d5f37b2c1dc"}', $instance->encrypt());
		$this->assertEquals('6161616161616161616161616161616161616161616161616161616161616161', $instance->getId());
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
			'url' => null,
			'method' => null,
		];

		$this->assertEquals($expected, $result);
		$this->assertEquals('deadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafedeadcafe', $instance->getId());
	}

	public function testRequestDataAssembly2()
	{
		$method = $this->callableMethod('getRequestData');
		$result = $method->invoke($instance = $this->expectsMockInstance(['data' => ['a' => $this->invalidUtf8String(), 'b' => M_PI, M_PI => null, $this->invalidUtf8String() => $this->invalidUtf8String()]]));

		$encoded_str = 'b' . base64_encode($this->invalidUtf8String());
		$expected = [
			'id' => '6161616161616161616161616161616161616161616161616161616161616161',
			'timestamp' => 1513694013,
			'headers' => ['uX-Foo' => [ 0 => 'uBar'], 'uX-Baz' => [0 => 'uFoo', 1 => 'uBar']],
			'data' => ['ua' => $encoded_str, 'ub' => M_PI, M_PI => null, $encoded_str => $encoded_str],
			'url' => null,
			'method' => null,
		];

		$this->assertEquals($expected, $result);
		$this->assertEquals('6161616161616161616161616161616161616161616161616161616161616161', $instance->getId());
	}

	/*
	 * INPUT TESTS - HEADERS
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
	 * INPUT TESTS - DATA
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
	 * INPUT TESTS - SHARED SECRETS
	 */

	public function testInvalidSharedSecrets1()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => null]);
	}

	public function testInvalidSharedSecrets2()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => null]);
	}

	public function testInvalidSharedSecrets3()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => M_PI]);
	}

	public function testInvalidSharedSecrets4()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => M_PI]);
	}

	public function testInvalidSharedSecrets5()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => 'foo']);
	}

	public function testInvalidSharedSecrets6()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => 'foo']);
	}

	public function testInvalidSharedSecrets7()
	{
		$secret = range(0, 31);
		$secret[31] = 'foo';
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => $secret]);
	}

	public function testInvalidSharedSecrets8()
	{
		$secret = range(0, 31);
		$secret[31] = 'foo';
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => $secret]);
	}

	public function testInvalidSharedSecrets9()
	{
		$secret = range(0, 31);
		$secret[16] = -1;
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => $secret]);
	}

	public function testInvalidSharedSecrets10()
	{
		$secret = range(0, 31);
		$secret[16] = -1;
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => $secret]);
	}

	public function testInvalidSharedSecrets11()
	{
		$secret = range(0, 31);
		$secret[16] = 256;
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => $secret]);
	}

	public function testInvalidSharedSecrets12()
	{
		$secret = range(0, 31);
		$secret[16] = 256;
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => $secret]);
	}

	public function testInvalidSharedSecrets13()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => fopen('php://temp', 'r+')]);
	}

	public function testInvalidSharedSecrets14()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => fopen('php://temp', 'r+')]);
	}

	public function testInvalidSharedSecrets15()
	{
		$secret = range(0, 31);
		$secret[13] = fopen('php://temp', 'r+');
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => $secret]);
	}

	public function testInvalidSharedSecrets16()
	{
		$secret = range(0, 31);
		$secret[13] = fopen('php://temp', 'r+');
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => $secret]);
	}

	public function testInvalidSharedSecrets17()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => range(0, 90), 'secret2' => range(0, 90)]);
	}

	public function testInvalidSharedSecrets18()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '01234567890123456789012345678912', 'secret2' => '01234567890123456789012345678912']);
	}

	public function testInvalidSharedSecrets19()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '01234567890123456789012345678912x', 'secret2' => '01234567890123456789012345678912']);
	}

	public function testInvalidSharedSecrets20()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '01234567890123456789012345678912', 'secret2' => '01234567890123456789012345678912x']);
	}

	public function testInvalidSharedSecrets21()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '0123456789012345678901234567891']);
	}

	public function testInvalidSharedSecrets22()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => '0123456789012345678901234567891']);
	}

	public function testInvalidSharedSecrets23()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => range(0, 30)]);
	}

	public function testInvalidSharedSecrets24()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => range(0, 30)]);
	}

	public function testInvalidSharedSecrets25()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => 'x01234567890123456789012345678912', 'secret2' => '01234567890123456789012345678912']);
	}

	public function testInvalidSharedSecrets26()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '01234567890123456789012345678912', 'secret2' => 'x01234567890123456789012345678912']);
	}

	public function testValidSharedSecrets1()
	{
		$this->expectsInstance(['secret1' => str_repeat($this->invalidUtf8String(), 4)]);
	}

	public function testValidSharedSecrets2()
	{
		$this->expectsInstance(['secret2' => str_repeat($this->invalidUtf8String(), 4)]);
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
	 * HELPER METHODS
	 */

	protected function expectsInstance(array $arguments_merge = [])
	{
		$this->assertInstanceOf(Encryptor::class, $instance = new Encryptor(...$this->constructorArguments($arguments_merge)));
		return $instance;
	}

	protected function expectsMockInstance(array $arguments_merge = [])
	{
		$instance = $this->getMockBuilder(Encryptor::class)->setMethods(['generateRandomBytes', 'getCurrentTimestamp'])->setConstructorArgs($this->constructorArguments($arguments_merge))->getMock();
		$instance->method('generateRandomBytes')->will($this->returnCallback(function ($length) { return str_repeat('a', $length); }));
		$instance->method('getCurrentTimestamp')->willReturn(1513694013);

		$this->assertInstanceOf(Encryptor::class, $instance);
		return $instance;
	}

	protected function expectsException($exception_class, array $arguments_merge = [])
	{
		$this->expectException($exception_class);
		return new Encryptor(...$this->constructorArguments($arguments_merge));
	}

	protected function constructorArguments(array $merge = [])
	{
		$args = [
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
		];

		$args = $merge + $args;

		return [$args['headers'], $args['data'], $args['secret1'], $args['secret2'], $args['force_id'], $args['url'], $args['method']];
	}

	protected function callableMethod($method_name)
	{
		$method = new ReflectionMethod(Encryptor::class, $method_name);
        $method->setAccessible(true);

        return $method;
	}

	protected function circularReferencedArray()
	{
		$a = ['foo' => 'bar'];
		$a[4] = &$a;

		return $a;
	}

	protected function invalidUtf8String()
	{
		return "abc\x00\xffcde";
	}

	protected function deepArray($levels)
	{
		$a = ['el' => rand()];
		$cur = &$a;

		for ($level = 0; $level < $levels - 1; $level++) {
			$cur['el2'] = ['el' => rand()];
			$cur = &$cur['el2'];
		}

		unset($cur);

		return $a;
	}

	protected function arrayDepth(array $array)
	{
		$max_depth = 1;

		foreach ($array as $value) {
			if (is_array($value)) {
				$depth = $this->arrayDepth($value) + 1;

				if ($depth > $max_depth) {
					$max_depth = $depth;
				}
			}
		}

		return $max_depth;
	}
}
