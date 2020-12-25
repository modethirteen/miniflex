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

class CryptoKey implements CryptoKeyInterface {
    const TYPE_PGP_PRIVATE_KEY_BLOCK = 'PGP PRIVATE KEY BLOCK';
    const TYPE_PGP_PUBLIC_KEY_BLOCK = 'PGP PUBLIC KEY BLOCK';
    const TYPE_CERTIFICATE = 'CERTIFICATE';
    const TYPE_PRIVATE_KEY = 'PRIVATE KEY';
    const TYPE_RSA_PRIVATE_KEY = 'RSA PRIVATE KEY';

    /**
     * @var int|null
     */
    private $expiration = null;

    /**
     * @var string|null
     */
    private $fingerprint = null;

    /**
     * @var string
     */
    private $formatted;

    /**
     * @var string|null
     */
    private $name = null;

    /**
     * @var string
     */
    private $text;

    /**
     * @var string
     */
    private $type;

    /**
     * @param string $type - key block type (CERTIFICATE, PGP PUBLIC KEY BLOCK, ...)
     * @param string $formatted - formatted key with header/footer
     * @param string $text - raw text representation of key
     */
    public function __construct(string $type, string $formatted, string $text) {
        $this->type = $type;
        $this->formatted = $formatted;
        $this->text = $text;
    }

    public function __toString() : string {
        return $this->toString();
    }

    public function getExpiration() : ?int {
        return $this->expiration;
    }

    public function getFingerprint() : ?string {
        return $this->fingerprint;
    }

    public function getName() : ?string {
        return $this->name;
    }

    public function getType() : string {
        return $this->type;
    }

    public function is(string $type) : bool {
        return $type === $this->type;
    }

    public function toString() : string {
        return $this->formatted;
    }

    public function toText() : string {
        return $this->text;
    }

    /**
     * @param int $expiration
     * @return static
     */
    public function withExpiration(int $expiration) : object {
        $key = clone $this;
        $key->expiration = $expiration;
        return $key;
    }

    /**
     * @param string $fingerprint
     * @return static
     */
    public function withFingerprint(string $fingerprint) : object {
        $key = clone $this;
        $key->fingerprint = $fingerprint;
        return $key;
    }

    /**
     * @param string $name
     * @return static
     */
    public function withName(string $name) : object {
        $key = clone $this;
        $key->name = $name;
        return $key;
    }
}
