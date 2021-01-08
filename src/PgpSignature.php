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

class PgpSignature implements SignatureInterface {

    /**
     * @var string
     */
    private $fingerprint;

    /**
     * @param string $fingerprint - PGP private key fingerprint
     */
    public function __construct(string $fingerprint) {
        $this->fingerprint = $fingerprint;
    }

    public function sign(string $text) : ?string {
        $gnupg = new gnupg();
        $gnupg->addsignkey($this->fingerprint);
        $result = $gnupg->sign($text);
        return $result !== false ? $result : null;
    }
}
