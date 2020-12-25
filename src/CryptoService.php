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

use gnupg;
use modethirteen\Crypto\Exception\CryptoServiceCannotGenerateSignedMessageException;
use modethirteen\TypeEx\StringEx;

class CryptoService implements CryptoServiceInterface {

    /**
     * {@inheritDoc}
     * @throws CryptoServiceCannotGenerateSignedMessageException
     */
    public function getSignedMessage(string $text, CryptoKeyInterface $key) : string {
        switch($key->getType()) {
            case CryptoKey::TYPE_PGP_PRIVATE_KEY_BLOCK:
                $fingerprint = $key->getFingerprint();
                if(StringEx::isNullOrEmpty($fingerprint)) {
                    throw new CryptoServiceCannotGenerateSignedMessageException($text, $key, 'Cannot retrieve fingerprint from PGP private key');
                }
                $gnupg = new gnupg();
                $gnupg->addsignkey($fingerprint);

                // gnupg::sign returns string|bool, but the docblock only declares string (failing static analysis)
                $result = StringEx::stringify($gnupg->sign($text));
                if($result === 'false') {
                    throw new CryptoServiceCannotGenerateSignedMessageException($text, $key, 'Signature failed');
                }
                return $result;
            default:
                throw new CryptoServiceCannotGenerateSignedMessageException($text, $key, 'Not implemented');
        }
    }
}
