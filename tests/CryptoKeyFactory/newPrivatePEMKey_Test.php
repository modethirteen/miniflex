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

class newPrivatePEMKey_Test extends AbstractCryptoTestCase {

    /**
     * @test
     */
    public function Can_get_private_PEM_key() : void {

        // arrange
        $factory = new CryptoKeyFactory();

        // act
        $key = $factory->newPrivatePEMKey(self::getPrivatePEMKeySourceText());

        // assert
        static::assertEquals(<<<TEXT
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAn5Jt/AmA9VdU4O8iEGrD7xmPPe5pvgCmop9/W/lsrr+m7UCj
klbb8cjxriKwrlrhJBZPFlETJAiqy7u4Jbzr1cluMwO3Z8kBBlwb4mhvTgu9ZPpC
A/V3FTVeNz/yOiWbNhi2YmTunozVZy3L2iBWoBz/JSlvG0ktoDm5uMREw49XTiwu
jKufzzU6Dbvs7MMTodIY7BbzedELOz8tyr92ymiQbUGW9kkxAPWQZC8+h2uNCQDN
Y7EvUVT5qD2Q89RdGEG4ZeYnv8VsULEbD6ZYW5lNa3HnzoKjtVIZuaBbT8sdWB8G
/w8gkvScAgcdl/cR7ix2y7kTYbSmTsBotLfsgQIDAQABAoIBAHARe/L1jb9A3Vi4
OblD8mWbEtHQ/iy18lHmKKEktKKp8QdRTU+6dvABS1McA+//3XzluheXSxUUjTdW
mEbQvuS/egiUBJv8PB8GU4MYC4vJjPM9G14CZ+baO1gcLfeOb8p3YqgJ8NgjWsED
FdcUvSHoG30y81g7dbLAt+G+3fhlOER6LcFv7zbLbWAfj9LBNghR77fMkf/1TZfR
cTr0iYADg7FI7A9WJplNx681GQ7JrsVJPJyy3KoL+gWMIygR540l8CY597isLi1f
HlcFRmJNjCfHcKYZnL5Iqx+v9v/YVzxfF6UsP8ZOAOgUsqjyS5C7hEjtWee3h7uG
gO4yIR0CgYEA0M2onHhM6SabVrSJuC/7rsjlnh3PIHqa9F2kAx96bWwZWZzxktEk
kQmX2vH30LnpmSW1VykWHFy93yqKlRgmPZJXDTVXr+UivPFDiU1nDA/Gv+OF1Fpq
nvAfKcs0szMaYLNAfJX2c4jlIe9FoPijqLeN8hh2tyX2+OeDLaQwOzMCgYEAw6QD
bt0JLDCSFAHDN7Bl1TlBxxEzS9D3r8vistzC34zyQkLm7T6+Wh9PVMj5GxMtl2jS
DlwdJ6yZLBHGLgUtdHy5wVeOaEQRg2tNFtPlwP/aJd766EdS/5qUvIDnupnfEUgn
wKef3Ad22aH5BM8KxN/KhkFO1jCewvMxezkumXsCgYEAw/eAu/mcFWYKfIHMj3VZ
PV2HQ7KuZskrDRWljNjKSlAeKqDFiQmIzCa4wuA9uUQDHZzqaPdCrTPNb9m5Xtzf
ZwIleVwLBCaFR9cXj5F5mTRlUEr1m6uQTcMHPG5e86COrRsO9t64Aw8EHak3LDCv
SPWc3w5evN2AwXJnBzsFmUkCgYB8fRMKKnA5xDZPsMdt2jsSMLrgVtuTNMdG/6+j
LMJ7yY4mB7g14qTxZ9btFm0cg1mRbMutA4QxyKw21KCMjBLeercghfxB8H5MZ6zI
B9G8u5EuY/K4dxojN1PJlyTdIihFMOrKtl8MfVttJJn2K2Co4dZXE5t8w7diSamE
xWAXnQKBgQCZuVZk+Lb46yjUN4ON/5f5tsRLTY0qbF75CCUqJbDu8Nws+rWe+TUI
wgPgIy18xlfhD2ZVFvPGNzhSn+jPZ5lxrW26zq1bQurQv4hmH17MQCkXcdQmGEtE
jGTyhXmuQm7YPbwiK0izLJjOLYQop0hBdqt+jtcNqPKd7XOY4OEmNA==
-----END RSA PRIVATE KEY-----

TEXT
, $key->toString());
        static::assertEquals(<<<TEXT
MIIEpAIBAAKCAQEAn5Jt/AmA9VdU4O8iEGrD7xmPPe5pvgCmop9/W/lsrr+m7UCjklbb8cjxriKwrlrhJBZPFlETJAiqy7u4Jbzr1cluMwO3Z8kBBlwb4mhvTgu9ZPpCA/V3FTVeNz/yOiWbNhi2YmTunozVZy3L2iBWoBz/JSlvG0ktoDm5uMREw49XTiwujKufzzU6Dbvs7MMTodIY7BbzedELOz8tyr92ymiQbUGW9kkxAPWQZC8+h2uNCQDNY7EvUVT5qD2Q89RdGEG4ZeYnv8VsULEbD6ZYW5lNa3HnzoKjtVIZuaBbT8sdWB8G/w8gkvScAgcdl/cR7ix2y7kTYbSmTsBotLfsgQIDAQABAoIBAHARe/L1jb9A3Vi4OblD8mWbEtHQ/iy18lHmKKEktKKp8QdRTU+6dvABS1McA+//3XzluheXSxUUjTdWmEbQvuS/egiUBJv8PB8GU4MYC4vJjPM9G14CZ+baO1gcLfeOb8p3YqgJ8NgjWsEDFdcUvSHoG30y81g7dbLAt+G+3fhlOER6LcFv7zbLbWAfj9LBNghR77fMkf/1TZfRcTr0iYADg7FI7A9WJplNx681GQ7JrsVJPJyy3KoL+gWMIygR540l8CY597isLi1fHlcFRmJNjCfHcKYZnL5Iqx+v9v/YVzxfF6UsP8ZOAOgUsqjyS5C7hEjtWee3h7uGgO4yIR0CgYEA0M2onHhM6SabVrSJuC/7rsjlnh3PIHqa9F2kAx96bWwZWZzxktEkkQmX2vH30LnpmSW1VykWHFy93yqKlRgmPZJXDTVXr+UivPFDiU1nDA/Gv+OF1FpqnvAfKcs0szMaYLNAfJX2c4jlIe9FoPijqLeN8hh2tyX2+OeDLaQwOzMCgYEAw6QDbt0JLDCSFAHDN7Bl1TlBxxEzS9D3r8vistzC34zyQkLm7T6+Wh9PVMj5GxMtl2jSDlwdJ6yZLBHGLgUtdHy5wVeOaEQRg2tNFtPlwP/aJd766EdS/5qUvIDnupnfEUgnwKef3Ad22aH5BM8KxN/KhkFO1jCewvMxezkumXsCgYEAw/eAu/mcFWYKfIHMj3VZPV2HQ7KuZskrDRWljNjKSlAeKqDFiQmIzCa4wuA9uUQDHZzqaPdCrTPNb9m5XtzfZwIleVwLBCaFR9cXj5F5mTRlUEr1m6uQTcMHPG5e86COrRsO9t64Aw8EHak3LDCvSPWc3w5evN2AwXJnBzsFmUkCgYB8fRMKKnA5xDZPsMdt2jsSMLrgVtuTNMdG/6+jLMJ7yY4mB7g14qTxZ9btFm0cg1mRbMutA4QxyKw21KCMjBLeercghfxB8H5MZ6zIB9G8u5EuY/K4dxojN1PJlyTdIihFMOrKtl8MfVttJJn2K2Co4dZXE5t8w7diSamExWAXnQKBgQCZuVZk+Lb46yjUN4ON/5f5tsRLTY0qbF75CCUqJbDu8Nws+rWe+TUIwgPgIy18xlfhD2ZVFvPGNzhSn+jPZ5lxrW26zq1bQurQv4hmH17MQCkXcdQmGEtEjGTyhXmuQm7YPbwiK0izLJjOLYQop0hBdqt+jtcNqPKd7XOY4OEmNA==
TEXT
, $key->toText());
        static::assertEquals('RSA PRIVATE KEY', $key->getType());
    }

    /**
     * @test
     */
    public function Can_get_null_private_PEM_key() : void {

        // arrange
        $factory = new CryptoKeyFactory();

        // act
        $key = $factory->newPrivatePEMKey('');

        // assert
        static::assertNull($key);
    }
}
