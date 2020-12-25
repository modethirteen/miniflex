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

class newX509Certificate_Test extends AbstractCryptoTestCase {

    /**
     * @test
     */
    public function Can_get_x509_certificate() : void {

        // arrange
        $factory = new CryptoKeyFactory();

        // act
        $key = $factory->newX509Certificate(self::getX509CertificateSourceText());

        // assert
        static::assertEquals(<<<TEXT
-----BEGIN CERTIFICATE-----
MIIDvDCCAqQCCQCZovg3nWlgVDANBgkqhkiG9w0BAQsFADCBnzELMAkGA1UEBhMC
SUUxDTALBgNVBAgMBENvcmsxDTALBgNVBAcMBENvcmsxGTAXBgNVBAoMEE1pbmRU
b3VjaERhcnJhZ2gxEDAOBgNVBAsMB1N1cHBvcnQxHjAcBgNVBAMMFWRhcnJhZ2hz
Lm1pbmR0b3VjaC51czElMCMGCSqGSIb3DQEJARYWZGFycmFnaHNAbWluZHRvdWNo
LmNvbTAeFw0xOTAzMTQxMDUwNDJaFw0yMDAzMTMxMDUwNDJaMIGfMQswCQYDVQQG
EwJJRTENMAsGA1UECAwEQ29yazENMAsGA1UEBwwEQ29yazEZMBcGA1UECgwQTWlu
ZFRvdWNoRGFycmFnaDEQMA4GA1UECwwHU3VwcG9ydDEeMBwGA1UEAwwVZGFycmFn
aHMubWluZHRvdWNoLnVzMSUwIwYJKoZIhvcNAQkBFhZkYXJyYWdoc0BtaW5kdG91
Y2guY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn5Jt/AmA9VdU
4O8iEGrD7xmPPe5pvgCmop9/W/lsrr+m7UCjklbb8cjxriKwrlrhJBZPFlETJAiq
y7u4Jbzr1cluMwO3Z8kBBlwb4mhvTgu9ZPpCA/V3FTVeNz/yOiWbNhi2YmTunozV
Zy3L2iBWoBz/JSlvG0ktoDm5uMREw49XTiwujKufzzU6Dbvs7MMTodIY7BbzedEL
Oz8tyr92ymiQbUGW9kkxAPWQZC8+h2uNCQDNY7EvUVT5qD2Q89RdGEG4ZeYnv8Vs
ULEbD6ZYW5lNa3HnzoKjtVIZuaBbT8sdWB8G/w8gkvScAgcdl/cR7ix2y7kTYbSm
TsBotLfsgQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAYytRVlEuO3bSY/y63cAHh
ioq6YrYM9LrPEY4S3lIuULEniGqwHt/RlCaAk5GA3fsn+Z9Sh55eS3TsLyEmDpuX
XyjZludpuh8AcVItpQKamkSycgMnlpx/yNg5yThRY1PYctDDwN+N+WbR8cwws8dt
RwV7jW53jJEPK0dX/Rd8Uc1753csrT6ZXZDUMg/jpSaqw1hKuVYTDgkxM8NJJHbA
prmdEeunjNGwsxyhk1HAHY4SLtTMfHylGfniebrf2r8VvxD1McOAhnWq9U67nbte
mcCzFF4TSb7cIbuqFW8gzcMrAWJOKnVwIARCNaE3rlfZ5h1mxI8/Rdoa+WgFsqXi
-----END CERTIFICATE-----

TEXT
, $key->toString());
        static::assertEquals(<<<TEXT
MIIDvDCCAqQCCQCZovg3nWlgVDANBgkqhkiG9w0BAQsFADCBnzELMAkGA1UEBhMCSUUxDTALBgNVBAgMBENvcmsxDTALBgNVBAcMBENvcmsxGTAXBgNVBAoMEE1pbmRUb3VjaERhcnJhZ2gxEDAOBgNVBAsMB1N1cHBvcnQxHjAcBgNVBAMMFWRhcnJhZ2hzLm1pbmR0b3VjaC51czElMCMGCSqGSIb3DQEJARYWZGFycmFnaHNAbWluZHRvdWNoLmNvbTAeFw0xOTAzMTQxMDUwNDJaFw0yMDAzMTMxMDUwNDJaMIGfMQswCQYDVQQGEwJJRTENMAsGA1UECAwEQ29yazENMAsGA1UEBwwEQ29yazEZMBcGA1UECgwQTWluZFRvdWNoRGFycmFnaDEQMA4GA1UECwwHU3VwcG9ydDEeMBwGA1UEAwwVZGFycmFnaHMubWluZHRvdWNoLnVzMSUwIwYJKoZIhvcNAQkBFhZkYXJyYWdoc0BtaW5kdG91Y2guY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn5Jt/AmA9VdU4O8iEGrD7xmPPe5pvgCmop9/W/lsrr+m7UCjklbb8cjxriKwrlrhJBZPFlETJAiqy7u4Jbzr1cluMwO3Z8kBBlwb4mhvTgu9ZPpCA/V3FTVeNz/yOiWbNhi2YmTunozVZy3L2iBWoBz/JSlvG0ktoDm5uMREw49XTiwujKufzzU6Dbvs7MMTodIY7BbzedELOz8tyr92ymiQbUGW9kkxAPWQZC8+h2uNCQDNY7EvUVT5qD2Q89RdGEG4ZeYnv8VsULEbD6ZYW5lNa3HnzoKjtVIZuaBbT8sdWB8G/w8gkvScAgcdl/cR7ix2y7kTYbSmTsBotLfsgQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAYytRVlEuO3bSY/y63cAHhioq6YrYM9LrPEY4S3lIuULEniGqwHt/RlCaAk5GA3fsn+Z9Sh55eS3TsLyEmDpuXXyjZludpuh8AcVItpQKamkSycgMnlpx/yNg5yThRY1PYctDDwN+N+WbR8cwws8dtRwV7jW53jJEPK0dX/Rd8Uc1753csrT6ZXZDUMg/jpSaqw1hKuVYTDgkxM8NJJHbAprmdEeunjNGwsxyhk1HAHY4SLtTMfHylGfniebrf2r8VvxD1McOAhnWq9U67nbtemcCzFF4TSb7cIbuqFW8gzcMrAWJOKnVwIARCNaE3rlfZ5h1mxI8/Rdoa+WgFsqXi
TEXT
, $key->toText());
        static::assertEquals('56235c17757561bb9fc580b11c6d5b6c19b4844a', $key->getFingerprint());
        static::assertEquals('_C=IE_ST=Cork_L=Cork_O=MindTouchDarragh_OU=Support_CN=darraghs.mindtouch.us_emailAddress=darraghs@mindtouch.com', $key->getName());
        static::assertEquals(1584096642, $key->getExpiration());
        static::assertEquals('CERTIFICATE', $key->getType());
    }

    /**
     * @test
     */
    public function Can_get_x509_certificate_with_sha256_fingerprint() : void {

        // arrange
        $text = <<<TEXT
-----BEGIN CERTIFICATE-----
MIIDvDCCAqQCCQCZovg3nWlgVDANBgkqhkiG9w0BAQsFADCBnzELMAkGA1UEBhMC
SUUxDTALBgNVBAgMBENvcmsxDTALBgNVBAcMBENvcmsxGTAXBgNVBAoMEE1pbmRU
b3VjaERhcnJhZ2gxEDAOBgNVBAsMB1N1cHBvcnQxHjAcBgNVBAMMFWRhcnJhZ2hz
Lm1pbmR0b3VjaC51czElMCMGCSqGSIb3DQEJARYWZGFycmFnaHNAbWluZHRvdWNo
LmNvbTAeFw0xOTAzMTQxMDUwNDJaFw0yMDAzMTMxMDUwNDJaMIGfMQswCQYDVQQG
EwJJRTENMAsGA1UECAwEQ29yazENMAsGA1UEBwwEQ29yazEZMBcGA1UECgwQTWlu
ZFRvdWNoRGFycmFnaDEQMA4GA1UECwwHU3VwcG9ydDEeMBwGA1UEAwwVZGFycmFn
aHMubWluZHRvdWNoLnVzMSUwIwYJKoZIhvcNAQkBFhZkYXJyYWdoc0BtaW5kdG91
Y2guY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn5Jt/AmA9VdU
4O8iEGrD7xmPPe5pvgCmop9/W/lsrr+m7UCjklbb8cjxriKwrlrhJBZPFlETJAiq
y7u4Jbzr1cluMwO3Z8kBBlwb4mhvTgu9ZPpCA/V3FTVeNz/yOiWbNhi2YmTunozV
Zy3L2iBWoBz/JSlvG0ktoDm5uMREw49XTiwujKufzzU6Dbvs7MMTodIY7BbzedEL
Oz8tyr92ymiQbUGW9kkxAPWQZC8+h2uNCQDNY7EvUVT5qD2Q89RdGEG4ZeYnv8Vs
ULEbD6ZYW5lNa3HnzoKjtVIZuaBbT8sdWB8G/w8gkvScAgcdl/cR7ix2y7kTYbSm
TsBotLfsgQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAYytRVlEuO3bSY/y63cAHh
ioq6YrYM9LrPEY4S3lIuULEniGqwHt/RlCaAk5GA3fsn+Z9Sh55eS3TsLyEmDpuX
XyjZludpuh8AcVItpQKamkSycgMnlpx/yNg5yThRY1PYctDDwN+N+WbR8cwws8dt
RwV7jW53jJEPK0dX/Rd8Uc1753csrT6ZXZDUMg/jpSaqw1hKuVYTDgkxM8NJJHbA
prmdEeunjNGwsxyhk1HAHY4SLtTMfHylGfniebrf2r8VvxD1McOAhnWq9U67nbte
mcCzFF4TSb7cIbuqFW8gzcMrAWJOKnVwIARCNaE3rlfZ5h1mxI8/Rdoa+WgFsqXi
-----END CERTIFICATE-----
TEXT;
        $factory = new CryptoKeyFactory('sha256');

        // act
        $key = $factory->newX509Certificate($text);

        // assert
        static::assertEquals('9e3b530abbcb0c644f116a1e195bf463c4be78f18bcfa262e728da22e97a77c3', $key->getFingerprint());
    }

    /**
     * @test
     */
    public function Can_get_null_x509_certificate() : void {

        // arrange
        $factory = new CryptoKeyFactory();

        // act
        $key = $factory->newX509Certificate('foo');

        // assert
        static::assertNull($key);
    }
}
