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

use modethirteen\Crypto\Exception\CryptoServiceCannotGenerateSignedMessageException;

class CryptoService implements CryptoServiceInterface {

    /**
     * @var SignatureFactoryInterface
     */
    private $pgpSignatureFactory;

    /**
     * @param SignatureFactoryInterface $pgpSignatureFactory
     */
    public function __construct(SignatureFactoryInterface $pgpSignatureFactory) {
        $this->pgpSignatureFactory = $pgpSignatureFactory;
    }

    /**
     * {@inheritDoc}
     * @throws CryptoServiceCannotGenerateSignedMessageException
     */
    public function getSignedMessage(string $text, CryptoKeyInterface $key) : string {
        switch($key->getType()) {
            case CryptoKey::TYPE_PGP_PRIVATE_KEY_BLOCK:
                $result = $this->pgpSignatureFactory->newSignature($key)->sign($text);
                if($result === null) {
                    throw new CryptoServiceCannotGenerateSignedMessageException($text, $key, 'Signature failed');
                }
                return $result;
            default:
                throw new CryptoServiceCannotGenerateSignedMessageException($text, $key, 'Not implemented');
        }
    }
}
