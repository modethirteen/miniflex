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
namespace modethirteen\Crypto\Tests\CryptoService;

use gnupg;
use modethirteen\Crypto\CryptoKeyFactory;
use modethirteen\Crypto\CryptoKeyInterface;
use modethirteen\Crypto\CryptoService;
use modethirteen\Crypto\Exception\CryptoServiceCannotGenerateSignedMessageException;
use modethirteen\Crypto\PgpSignatureFactory;
use modethirteen\Crypto\Tests\AbstractCryptoTestCase;

class getSignedMessage_Test extends AbstractCryptoTestCase {

    /**
     * @return array
     */
    public static function nonImplementedCryptoKey_Provider() : array {
        return [
            [(new CryptoKeyFactory())->newPublicPGPKey(self::getPgpKeyPairSource()->getPublicKeySourceText())],
            [(new CryptoKeyFactory())->newPrivatePEMKey(self::getPrivatePEMKeySourceText())],
            [(new CryptoKeyFactory())->newX509Certificate(self::getX509CertificateSourceText())],
        ];
    }

    /**
     * @test
     * @throws CryptoServiceCannotGenerateSignedMessageException
     */
    public function Can_get_message_signed_with_private_pgp() : void {

        // arrange
        $key = (new CryptoKeyFactory())->newPrivatePGPKey(self::getPgpKeyPairSource()->getPrivateKeySourceText());
        $message = <<<TEXT
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
TEXT;
        $service = new CryptoService(new PgpSignatureFactory());

        // act
        $result = $service->getSignedMessage($message, $key);

        // assert
        $results = (new gnupg())->verify($result, false);
        if(!is_array($results)) {
            static::fail('Cannot verify signed message');
        }
        $fingerprints = array_map(function(array $result) {
            return isset($result['fingerprint']) ? $result['fingerprint'] : null;
        }, $results);
        $fingerprints = array_filter($fingerprints, 'strlen');
        $pgp = (new CryptoKeyFactory())->newPublicPGPKey(self::getPgpKeyPairSource()->getPublicKeySourceText());
        if(!in_array($pgp->getFingerprint(), $fingerprints)) {
            static::fail('Cannot find PGP public key fingerprint in message signature');
        } else {
            static::addToAssertionCount(1);
        }
    }

    /**
     * @dataProvider nonImplementedCryptoKey_Provider
     * @test
     * @param CryptoKeyInterface $nonImplementedCryptoKey
     * @throws CryptoServiceCannotGenerateSignedMessageException
     */
    public function Can_handle_non_implemented_signature_key_types(CryptoKeyInterface $nonImplementedCryptoKey) : void {

        // assert
        static::expectException(CryptoServiceCannotGenerateSignedMessageException::class);

        // arrange
        $message = <<<TEXT
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
TEXT;
        $service = new CryptoService(new PgpSignatureFactory());

        // act
        $service->getSignedMessage($message, $nonImplementedCryptoKey);
    }
}
