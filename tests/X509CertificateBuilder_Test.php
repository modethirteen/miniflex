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
namespace modethirteen\Crypto\Tests;

use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;
use modethirteen\Crypto\Exception\CryptoKeySignerException;
use modethirteen\Crypto\RsaPkcs8CryptoKeyPairFactory;
use modethirteen\Crypto\X509CertificateBuilder;

class X509CertificateBuilder_Test extends AbstractCryptoTestCase {

    /**
     * @test
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws CryptoKeySignerException
     */
    public function Can_build_and_sign_certificate() : void {

        // arrange
        $pair = (new RsaPkcs8CryptoKeyPairFactory())->newCryptoKeyPair();
        $builder = new X509CertificateBuilder($pair->getPrivateKey());

        // act
        $certificate = $builder
            ->setCommonName('foo')
            ->setCountryName('CA')
            ->setLocalityName('bar')
            ->setOrganizationalUnitName('qux')
            ->setOrganizationName('xyzzy')
            ->setStateOrProvinceName('plugh')
            ->setEmailAddress('fred@example.com')
            ->toSignedCryptoKey();

        // assert
        static::assertTrue(
            openssl_x509_check_private_key(
                openssl_x509_read($certificate->toString()),
                openssl_pkey_get_private($pair->getPrivateKey()->toString())
            )
        );
        static::assertEquals('CERTIFICATE', $certificate->getFormat());
        static::assertEquals('_CN=foo_C=CA_L=bar_OU=qux_O=xyzzy_ST=plugh_emailAddress=fred@example.com', $certificate->getName());
        static::assertIsInt($certificate->getExpiration());
    }
}
