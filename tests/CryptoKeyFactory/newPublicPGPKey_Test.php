<?php declare(strict_types=1);
/**
 * modethirteen/miniflex
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace modethirteen\Crypto\Tests\CryptoKeyFactory;

use modethirteen\Crypto\CryptoKeyFactory;
use modethirteen\Crypto\Tests\AbstractCryptoTestCase;

class newPublicPGPKey_Test extends AbstractCryptoTestCase {

    /**
     * @test
     */
    public function Can_get_public_PGP_key() : void {

        // arrange
        $factory = new CryptoKeyFactory();

        // act
        $key = $factory->newPublicPGPKey(self::getPgpKeyPairSource()->getPublicKeySourceText());

        // assert
        static::assertEquals(<<<TEXT
-----BEGIN PGP PUBLIC KEY BLOCK-----
mQENBF7pY2YBCADNK7wZgyxSbj4hd6uJ3rEk4pSwIxCxDBdi95NTXX8nAh5AuTyb
FNBud+jlmheQy+o0ikIIFJmxz5gbEfXNCzgz6B0zgTnB1x0PIkwEapGUgeofgv+H
JZW6CQQY318oTgYkM9ap9T44ge98ryWTNR14B0aKKyCN9VkjuF7wnxo1ZrXJqHB9
TEdcqRZWVEYlSVc/+9y4Uk0qNtWyJ8+yW09bfMAr4NuOSgFODr24FckBsT7MQsvN
8YWHsO0LILzhi3suEWd1c1zw0iiP4YD0FJ790K5V0cImiZcyr12uE7KNK3TiO7bL
ozGzlHC+ziT16MW2ZaLZ/+7Gh0v00Fnvn+otABEBAAG0DWRla2ktd2ViL3Rlc3SJ
AVQEEwEIAD4WIQQcY2J1hLONjj3iV8OXpiXG2MfI9gUCXuljZgIbAwUJA8IaSgUL
CQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRCXpiXG2MfI9nRDB/4xQNsutcwmWMML
8iUUTrSJs6RoH3AUl0qkYcTY+fU2sV+O/lKauMHF39aN2pgUVVo6Ncf9ki6Pp6eU
atb6b1sDCvylpG5pVME0T0CdOozlYZn+/+QSiia4pDLrC7+XEEPzxqZIM59Zk+eC
GoO8RSdBv7CSl9kzscaGibCOyknhWdsGqWmyf8eQm8zY3a7B3PiV1zXMe2RTlz/A
ouWyDfTt48bgrKKxd0rPhWaLFJ65r9Op+vRKaTZYucHu8YcphEyYG6QQ3qXEPD0c
r4OPYSKyMiiBMLW4z1912DW8F61fea+d28c2N6vQqaQRmtz9DLOpy/AWeUPt/N9a
wgJo2QHAuQENBF7pY2YBCACzlOgu8keGPzEEVU0JjXfzRNYXS44ER1HRSNlecb0r
q7e0EIttOVYvsYFbWLmagDRHDsoHn2/44jJczA0l/1OGq1vQmASEE5uKMbIfMIs4
tuHRP6E59JTJZ0Odlm9mB/rdJGA/HXArpoU5UHZycXnobkaq/707cfUgiPv+k7MW
DxGVigbBmupMJYX1rR1et0mBQmmfyM5/KwC3QP6EX6iXloROXgKL9VuNOPq6qWEq
pbROzZNEJ87cTX+oxhE4/kneeoGKYFN0iEZwC2f4JMim6unhuioGYXnlgJu7xWWU
wK1HdcRjZmIrmKLLLMVyrLmdvV/ATjv44RzQZbHSN3WrABEBAAGJATwEGAEIACYW
IQQcY2J1hLONjj3iV8OXpiXG2MfI9gUCXuljZgIbDAUJA8IaSgAKCRCXpiXG2MfI
9mx3CACeV2+EKqkh/KH/Q7eepAnQwfpt8SKNCzaUDfLxkvGWi9imZO7VRvmD/zv8
6PCPXuiwkVkfvS3Ia6u5/zJDozywy8e/g03lOdxxoIC1vF4e49I8xk6m9OuR/hRY
kRlixrF3gcONStsRmFE46u7VA+43NNLpcnu8IrsmmHF4zF0ZCwDLx+CXTPvqbEWe
+HvrUKf2itJ6JS7GwIPR/oWKKBmKSk+Xp7BPom3R3SK0AQYn++qku5BeV/yHy3s+
PswrP0kho9JfMxnq+89xEgNaQGJdUgOWi7bjQx8VxAdvPES5lmAeDAvBjAiXSg18
Kt6n86nWIMcKGGi444MyACNA3Aqj=wRb+
-----END PGP PUBLIC KEY BLOCK-----

TEXT
, $key->toString());
        static::assertEquals(<<<TEXT
mQENBF7pY2YBCADNK7wZgyxSbj4hd6uJ3rEk4pSwIxCxDBdi95NTXX8nAh5AuTybFNBud+jlmheQy+o0ikIIFJmxz5gbEfXNCzgz6B0zgTnB1x0PIkwEapGUgeofgv+HJZW6CQQY318oTgYkM9ap9T44ge98ryWTNR14B0aKKyCN9VkjuF7wnxo1ZrXJqHB9TEdcqRZWVEYlSVc/+9y4Uk0qNtWyJ8+yW09bfMAr4NuOSgFODr24FckBsT7MQsvN8YWHsO0LILzhi3suEWd1c1zw0iiP4YD0FJ790K5V0cImiZcyr12uE7KNK3TiO7bLozGzlHC+ziT16MW2ZaLZ/+7Gh0v00Fnvn+otABEBAAG0DWRla2ktd2ViL3Rlc3SJAVQEEwEIAD4WIQQcY2J1hLONjj3iV8OXpiXG2MfI9gUCXuljZgIbAwUJA8IaSgULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRCXpiXG2MfI9nRDB/4xQNsutcwmWMML8iUUTrSJs6RoH3AUl0qkYcTY+fU2sV+O/lKauMHF39aN2pgUVVo6Ncf9ki6Pp6eUatb6b1sDCvylpG5pVME0T0CdOozlYZn+/+QSiia4pDLrC7+XEEPzxqZIM59Zk+eCGoO8RSdBv7CSl9kzscaGibCOyknhWdsGqWmyf8eQm8zY3a7B3PiV1zXMe2RTlz/AouWyDfTt48bgrKKxd0rPhWaLFJ65r9Op+vRKaTZYucHu8YcphEyYG6QQ3qXEPD0cr4OPYSKyMiiBMLW4z1912DW8F61fea+d28c2N6vQqaQRmtz9DLOpy/AWeUPt/N9awgJo2QHAuQENBF7pY2YBCACzlOgu8keGPzEEVU0JjXfzRNYXS44ER1HRSNlecb0rq7e0EIttOVYvsYFbWLmagDRHDsoHn2/44jJczA0l/1OGq1vQmASEE5uKMbIfMIs4tuHRP6E59JTJZ0Odlm9mB/rdJGA/HXArpoU5UHZycXnobkaq/707cfUgiPv+k7MWDxGVigbBmupMJYX1rR1et0mBQmmfyM5/KwC3QP6EX6iXloROXgKL9VuNOPq6qWEqpbROzZNEJ87cTX+oxhE4/kneeoGKYFN0iEZwC2f4JMim6unhuioGYXnlgJu7xWWUwK1HdcRjZmIrmKLLLMVyrLmdvV/ATjv44RzQZbHSN3WrABEBAAGJATwEGAEIACYWIQQcY2J1hLONjj3iV8OXpiXG2MfI9gUCXuljZgIbDAUJA8IaSgAKCRCXpiXG2MfI9mx3CACeV2+EKqkh/KH/Q7eepAnQwfpt8SKNCzaUDfLxkvGWi9imZO7VRvmD/zv86PCPXuiwkVkfvS3Ia6u5/zJDozywy8e/g03lOdxxoIC1vF4e49I8xk6m9OuR/hRYkRlixrF3gcONStsRmFE46u7VA+43NNLpcnu8IrsmmHF4zF0ZCwDLx+CXTPvqbEWe+HvrUKf2itJ6JS7GwIPR/oWKKBmKSk+Xp7BPom3R3SK0AQYn++qku5BeV/yHy3s+PswrP0kho9JfMxnq+89xEgNaQGJdUgOWi7bjQx8VxAdvPES5lmAeDAvBjAiXSg18Kt6n86nWIMcKGGi444MyACNA3Aqj=wRb+
TEXT
, $key->toText());
        static::assertEquals('1C63627584B38D8E3DE257C397A625C6D8C7C8F6', $key->getFingerprint());
        static::assertEquals('PGP PUBLIC KEY BLOCK', $key->getType());
    }

    /**
     * @test
     */
    public function Can_get_null_public_PGP_key() : void {

        // arrange
        $factory = new CryptoKeyFactory();

        // act
        $key = $factory->newPublicPGPKey('foo');

        // assert
        static::assertNull($key);
    }
}
