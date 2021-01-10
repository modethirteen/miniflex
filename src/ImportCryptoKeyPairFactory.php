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

use modethirteen\Crypto\Exception\CryptoKeyCannotParseCryptoKeyTextException;
use modethirteen\Crypto\Exception\CryptoKeyFactoryCannotConstructCryptoKeyException;

class ImportCryptoKeyPairFactory implements CryptoKeyPairFactoryInterface {

    /**
     * @var string
     */
    private $algo = CryptoKey::DIGEST_ALGORITHM;

    /**
     * @var string
     */
    private $privateKeyText;

    /**
     * @var string
     */
    private $publicKeyText;

    /**
     * @param string $privateKeyText - PEM private key text
     * @param string $publicKeyText - PEM public key text
     */
    public function __construct(string $privateKeyText, string $publicKeyText) {
        $this->privateKeyText = $privateKeyText;
        $this->publicKeyText = $publicKeyText;
    }

    /**
     * {@inheritDoc}
     * @TODO (modethirteen, 20200616): validate key/pair relationships
     * @throws CryptoKeyFactoryCannotConstructCryptoKeyException
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     */
    public function newCryptoKeyPair(): CryptoKeyPair {
        return new CryptoKeyPair(
            (new ImportCryptoKeyFactory($this->privateKeyText))
                ->withDigestAlgorithm($this->algo)
                ->newCryptoKey(),
            (new ImportCryptoKeyFactory($this->publicKeyText))
                ->withDigestAlgorithm($this->algo)
                ->newCryptoKey()
        );
    }

    /**
     * @param string $algo - key fingerprint/digest algorithm
     * @return static
     */
    public function withDigestAlgorithm(string $algo) : object {
        $instance = clone $this;
        $instance->algo = $algo;
        return $instance;
    }
}
