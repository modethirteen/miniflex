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

class CryptoKey implements CryptoKeyInterface {
    const DIGEST_ALGORITHM = 'sha256';
    const FORMAT_CERTIFICATE = 'CERTIFICATE';
    const FORMAT_PGP_PRIVATE_KEY_BLOCK = 'PGP PRIVATE KEY BLOCK';
    const FORMAT_PGP_PUBLIC_KEY_BLOCK = 'PGP PUBLIC KEY BLOCK';
    const FORMAT_PRIVATE_KEY = 'PRIVATE KEY';
    const FORMAT_PUBLIC_KEY = 'PUBLIC KEY';
    const FORMAT_RSA_PRIVATE_KEY = 'RSA PRIVATE KEY';
    const FORMAT_RSA_PUBLIC_KEY = 'RSA PUBLIC KEY';

    /**
     * @var string[]
     */
    private static $supportedFormats = [
        self::FORMAT_CERTIFICATE,
        self::FORMAT_PGP_PRIVATE_KEY_BLOCK,
        self::FORMAT_PGP_PUBLIC_KEY_BLOCK,
        self::FORMAT_PRIVATE_KEY,
        self::FORMAT_PUBLIC_KEY,
        self::FORMAT_RSA_PRIVATE_KEY,
        self::FORMAT_RSA_PUBLIC_KEY
    ];

    /**
     * @param string $format - key block format (CERTIFICATE, PGP PUBLIC KEY BLOCK, ...)
     * @return bool
     */
    public static function isSupportedCryptoKeyFormat(string $format) : bool {
        return in_array($format, self::$supportedFormats);
    }

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
    private $format;

    /**
     * @var string
     */
    private $pem;

    /**
     * @var string|null
     */
    private $name = null;

    /**
     * @var string
     */
    private $text;

    /**
     * @param string $text - PEM key text
     * @param string|null $format - PEM key block format (default: infer from PEM key text)
     * @throws CryptoKeyCannotParseCryptoKeyTextException
     */
    public function __construct(string $text, string $format = null) {
        $x = ($format !== null ? new CryptoStringEx($text, $format) : new CryptoStringEx($text));
        $this->format = $x->getFormat();
        if(!self::isSupportedCryptoKeyFormat($this->format)) {
            throw new CryptoKeyCannotParseCryptoKeyTextException('invalid key block format', $text);
        }

        // save trimmed text
        $x = $x->trim();
        $this->text = $x->toString();

        // save PEM formatted text
        $x = $x->pem();
        $this->pem = $x->toString();
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

    public function getFormat() : string {
        return $this->format;
    }

    public function is(string $type) : bool {
        return $type === $this->format;
    }

    public function toString() : string {
        return $this->pem;
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
