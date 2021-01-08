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
namespace modethirteen\Crypto\Tests\PgpSignatureFactory;

use modethirteen\Crypto\CryptoKey;
use modethirteen\Crypto\CryptoKeyFactory;
use modethirteen\Crypto\Exception\SignatureFactoryCannotRetrieveFingerprintException;
use modethirteen\Crypto\PgpSignatureFactory;
use modethirteen\Crypto\Tests\AbstractCryptoTestCase;

class newSignature_Test extends AbstractCryptoTestCase {

    /**
     * @test
     */
    public function Can_handle_no_pgp_fingerprint() : void {

        // assert
        static::expectException(SignatureFactoryCannotRetrieveFingerprintException::class);

        // arrange
        $key = (new CryptoKeyFactory())->newPrivatePGPKey(self::getPgpKeyPairSource()->getPrivateKeySourceText());
        if($key instanceof CryptoKey) {
            $key = $key->withFingerprint('');
        }
        $factory = new PgpSignatureFactory();

        // act
        $factory->newSignature($key);
    }
}
