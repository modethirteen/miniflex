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
namespace modethirteen\Crypto;

class CryptoKeyPair {

    /**
     * @var CryptoKeyInterface
     */
    private CryptoKeyInterface $privateKey;

    /**
     * @var CryptoKeyInterface
     */
    private CryptoKeyInterface $publicKey;

    /**
     * @param CryptoKeyInterface $privateKey
     * @param CryptoKeyInterface $publicKey
     */
    public function __construct(CryptoKeyInterface $privateKey, CryptoKeyInterface $publicKey) {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    /**
     * @return CryptoKeyInterface
     */
    public function getPrivateKey() : CryptoKeyInterface {
        return $this->privateKey;
    }

    /**
     * @return CryptoKeyInterface
     */
    public function getPublicKey() : CryptoKeyInterface {
        return $this->publicKey;
    }
}
