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

interface CryptoKeyInterface {

    /**
     * @return int|null
     */
    public function getExpiration() : ?int;

    /**
     * @return string|null
     */
    public function getFingerprint() : ?string;

    /**
     * @return string|null
     */
    public function getName() : ?string;

    /**
     * @return string
     */
    public function getType() : string;

    /**
     * @param string $type
     * @return bool
     */
    public function is(string $type) : bool;

    /**
     * @return string
     */
    public function toString() : string;

    /**
     * Return a raw text representation of the key without header/footer
     *
     * @return string
     */
    public function toText() : string;
}
