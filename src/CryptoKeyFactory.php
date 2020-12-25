<?php
/** @noinspection DuplicatedCode */
declare(strict_types=1);
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
use modethirteen\TypeEx\StringEx;

class CryptoKeyFactory implements CryptoKeyFactoryInterface {
    const FINGERPRINT_ALGORITIM = 'sha1';

    /**
     * Reformat key text and add normalized header/footer
     *
     * @param string $text - unformatted key text
     * @param string $type - crypto key block name
     * @return string
     */
    private static function format(string $text, string $type) : string {
        return "-----BEGIN {$type}-----\n" . chunk_split($text, 64, "\n") . "-----END {$type}-----\n";
    }

    /**
     * @param string $text
     * @return string|null
     */
    private static function text(string $text) : ?string {
        $text = str_replace(["\x0D", "\r", "\n"], '', $text);
        if(!StringEx::isNullOrEmpty($text)) {
            $text = preg_replace('/-----(BEGIN|END) .+?-----/', '', $text);
            $text = str_replace(' ', '', $text);
        }
        return !StringEx::isNullOrEmpty($text) ? $text : null;
    }

    /**
     * @var string
     */
    private $algo;

    /**
     * @TODO (modethirteen, 20200616): use provided fingerprint algo in digests for PEM and PGP key fingerprints
     * @param string $algo - x.509 fingerprint algorithm
     */
    public function __construct(string $algo = self::FINGERPRINT_ALGORITIM) {
        $this->algo = $algo;
    }

    public function newPrivatePEMKey(string $text) : ?CryptoKeyInterface {
        $type = CryptoKey::TYPE_PRIVATE_KEY;
        if(!(new StringEx($text))->contains( "-----BEGIN {$type}-----")) {
            $type = CryptoKey::TYPE_RSA_PRIVATE_KEY;
        }
        $text = self::text($text);
        if($text === null) {
            return null;
        }
        $formatted = self::format($text, $type);

        // TODO (modethirteen, 20200616): validate format, get fingerprint, get expiration
        return new CryptoKey($type, $formatted, $text);
    }

    public function newPrivatePGPKey(string $text) : ?CryptoKeyInterface {
        $text = self::text($text);
        if($text === null) {
            return null;
        }
        $formatted = self::format($text, CryptoKey::TYPE_PGP_PRIVATE_KEY_BLOCK);
        $key = new CryptoKey(CryptoKey::TYPE_PGP_PRIVATE_KEY_BLOCK, $formatted, $text);
        $data = (new gnupg())->import($formatted);
        if(!is_array($data)) {
            return null;
        }
        if(isset($data['fingerprint'])) {
            $key = $key->withFingerprint($data['fingerprint']);
        }

        // TODO (modethirteen, 20200616): validate format, get expiration
        return $key;
    }

    public function newPublicPGPKey(string $text) : ?CryptoKeyInterface {
        $text = self::text($text);
        if($text === null) {
            return null;
        }
        $formatted = self::format($text, CryptoKey::TYPE_PGP_PUBLIC_KEY_BLOCK);
        $key = new CryptoKey(CryptoKey::TYPE_PGP_PUBLIC_KEY_BLOCK, $formatted, $text);
        $data = (new gnupg())->import($formatted);
        if(!is_array($data)) {
            return null;
        }
        if(isset($data['fingerprint'])) {
            $key = $key->withFingerprint($data['fingerprint']);
        }

        // TODO (modethirteen, 20200616): validate format, get expiration
        return $key;
    }

    public function newX509Certificate(string $text) : ?CryptoKeyInterface {
        $text = self::text($text);
        if($text === null) {
            return null;
        }
        $formatted = self::format($text, CryptoKey::TYPE_CERTIFICATE);
        $key = new CryptoKey(CryptoKey::TYPE_CERTIFICATE, $formatted, $text);
        $certificate = openssl_x509_read($formatted);
        if($certificate === false) {
            return null;
        }
        $data = openssl_x509_parse($certificate);
        $data = is_array($data) ? $data : [];
        if(isset($data['name'])) {
            $name = str_replace(['/', ' '], ['_', ''], $data['name']);
            if(!StringEx::isNullOrEmpty($name)) {
                $key = $key->withName($name);
            }
        }
        if(isset($data['validTo_time_t'])) {
            $key = $key->withExpiration(intval($data['validTo_time_t']));
        }
        $fingerprint = openssl_x509_fingerprint($certificate, $this->algo);
        if(!is_bool($fingerprint)) {
            $key = $key->withFingerprint($fingerprint);
        }
        openssl_x509_free($certificate);
        return $key;
    }
}
