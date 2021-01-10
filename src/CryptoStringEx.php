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

use modethirteen\TypeEx\StringEx;

class CryptoStringEx {

    /**
     * Remove PEM headers and whitespace
     *
     * @param string $text
     * @return string
     */
    private static function _trim(string $text) : string {
        $text = str_replace(["\x0D", "\r", "\n"], '', $text);
        if(!StringEx::isNullOrEmpty($text)) {
            $text = preg_replace('/-----(BEGIN|END) .+?-----/', '', $text);
            $text = str_replace(' ', '', $text);
        }
        return $text;
    }

    /**
     * @var string|null
     */
    private $format;

    /**
     * @var string
     */
    private $text;

    /**
     * @var bool
     */
    private $trimmed = false;

    /**
     * @param string $text - PEM key text
     * @param string|null $format - PEM key block format (default: infer from PEM key text)
     */
    public function __construct(string $text, string $format = null) {
        $this->text = $text;
        if($format === null && preg_match('/-----BEGIN (.+?)-----/', $text, $matches)) {
            $this->format = isset($matches[1]) ? $matches[1] : null;
        } else {
            $this->format = $format;
        }
    }

    /**
     * @return string
     */
    public function __toString() : string {
        return $this->toString();
    }

    /**
     * @return string
     */
    public function getFormat() : string {
        return $this->format;
    }

    /**
     * Remove PEM headers and whitespace
     *
     * @return static
     */
    public function trim() : object {
        $instance = clone $this;
        $instance->text = self::_trim($this->text);
        $instance->trimmed = true;
        return $instance;
    }

    /**
     * Add PEM headers and whitespace
     *
     * @return static
     */
    public function pem() : object {
        $instance = clone $this;
        $text = $this->trimmed ? $this->text : self::_trim($this->text);

        /** @noinspection PhpRedundantOptionalArgumentInspection */
        $instance->text = "-----BEGIN {$this->format}-----\n" . chunk_split($text, 64, "\n") . "-----END {$this->format}-----\n";
        $instance->trimmed = false;
        return $instance;
    }

    /**
     * @return string
     */
    public function toString() : string {
        return $this->text;
    }
}
