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
namespace modethirteen\Crypto\Tests;

use PHPUnit\Framework\TestCase;

interface PhpKeyPairSourceInterface {

    /**
     * @return string
     */
    function getPrivateKeySourceText() : string;

    /**
     * @return string
     */
    function getPublicKeySourceText() : string;
}

abstract class AbstractCryptoTestCase extends TestCase {

    /**
     * @return string
     */
    protected static function getPrivatePEMKeySourceText() : string {
        return <<<TEXT
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAn5Jt/AmA9VdU4O8iEGrD7xmPPe5pvgCmop9/W/lsrr+m7UCj klbb8cjxriKwrlrhJBZPFlETJAiqy7u4Jbzr1cluMwO3Z8kBBlwb4mhvTgu9ZPpC A/V3FTVeNz/yOiWbNhi2YmTunozVZy3L2iBWoBz/JSlvG0ktoDm5uMREw49XTiwu jKufzzU6Dbvs7MMTodIY7BbzedELOz8tyr92ymiQbUGW9kkxAPWQZC8+h2uNCQDN Y7EvUVT5qD2Q89RdGEG4ZeYnv8VsULEbD6ZYW5lNa3HnzoKjtVIZuaBbT8sdWB8G /w8gkvScAgcdl/cR7ix2y7kTYbSmTsBotLfsgQIDAQABAoIBAHARe/L1jb9A3Vi4 OblD8mWbEtHQ/iy18lHmKKEktKKp8QdRTU+6dvABS1McA+//3XzluheXSxUUjTdW mEbQvuS/egiUBJv8PB8GU4MYC4vJjPM9G14CZ+baO1gcLfeOb8p3YqgJ8NgjWsED FdcUvSHoG30y81g7dbLAt+G+3fhlOER6LcFv7zbLbWAfj9LBNghR77fMkf/1TZfR cTr0iYADg7FI7A9WJplNx681GQ7JrsVJPJyy3KoL+gWMIygR540l8CY597isLi1f HlcFRmJNjCfHcKYZnL5Iqx+v9v/YVzxfF6UsP8ZOAOgUsqjyS5C7hEjtWee3h7uG gO4yIR0CgYEA0M2onHhM6SabVrSJuC/7rsjlnh3PIHqa9F2kAx96bWwZWZzxktEk kQmX2vH30LnpmSW1VykWHFy93yqKlRgmPZJXDTVXr+UivPFDiU1nDA/Gv+OF1Fpq nvAfKcs0szMaYLNAfJX2c4jlIe9FoPijqLeN8hh2tyX2+OeDLaQwOzMCgYEAw6QD bt0JLDCSFAHDN7Bl1TlBxxEzS9D3r8vistzC34zyQkLm7T6+Wh9PVMj5GxMtl2jS DlwdJ6yZLBHGLgUtdHy5wVeOaEQRg2tNFtPlwP/aJd766EdS/5qUvIDnupnfEUgn wKef3Ad22aH5BM8KxN/KhkFO1jCewvMxezkumXsCgYEAw/eAu/mcFWYKfIHMj3VZ PV2HQ7KuZskrDRWljNjKSlAeKqDFiQmIzCa4wuA9uUQDHZzqaPdCrTPNb9m5Xtzf ZwIleVwLBCaFR9cXj5F5mTRlUEr1m6uQTcMHPG5e86COrRsO9t64Aw8EHak3LDCv SPWc3w5evN2AwXJnBzsFmUkCgYB8fRMKKnA5xDZPsMdt2jsSMLrgVtuTNMdG/6+j LMJ7yY4mB7g14qTxZ9btFm0cg1mRbMutA4QxyKw21KCMjBLeercghfxB8H5MZ6zI B9G8u5EuY/K4dxojN1PJlyTdIihFMOrKtl8MfVttJJn2K2Co4dZXE5t8w7diSamE xWAXnQKBgQCZuVZk+Lb46yjUN4ON/5f5tsRLTY0qbF75CCUqJbDu8Nws+rWe+TUI wgPgIy18xlfhD2ZVFvPGNzhSn+jPZ5lxrW26zq1bQurQv4hmH17MQCkXcdQmGEtE jGTyhXmuQm7YPbwiK0izLJjOLYQop0hBdqt+jtcNqPKd7XOY4OEmNA==
-----END RSA PRIVATE KEY-----
TEXT;
    }

    /**
     * @return PhpKeyPairSourceInterface
     */
    protected static function getPgpKeyPairSource() : object {
        return new class() implements PhpKeyPairSourceInterface {

            /**
             * @var string
             */
            private static $privateKeySourceText = <<<TEXT
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
jAiXSg18Kt6n86nWIMcKGGi444MyACNA3Aqj
=iBp5
-----END PGP PRIVATE KEY BLOCK-----
TEXT;
            /**
             * @var string
             */
            private static $publicKeySourceText = <<<TEXT
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF7pY2YBCADNK7wZgyxSbj4hd6uJ3rEk4pSwIxCxDBdi95NTXX8nAh5AuTyb
FNBud+jlmheQy+o0ikIIFJmxz5gbEfXNCzgz6B0zgTnB1x0PIkwEapGUgeofgv+H
JZW6CQQY318oTgYkM9ap9T44ge98ryWTNR14B0aKKyCN9VkjuF7wnxo1ZrXJqHB9
TEdcqRZWVEYlSVc/+9y4Uk0qNtWyJ8+yW09bfMAr4NuOSgFODr24FckBsT7MQsvN
8YWHsO0LILzhi3suEWd1c1zw0iiP4YD0FJ790K5V0cImiZcyr12uE7KNK3TiO7bL
ozGzlHC+ziT16MW2ZaLZ/+7Gh0v00Fnvn+otABEBAAG0DWRla2ktd2ViL3Rlc3SJ
AVQEEwEIAD4WIQQcY2J1hLONjj3iV8OXpiXG2MfI9gUCXuljZgIbAwUJA8IaSgUL
CQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRCXpiXG2MfI9nRDB/4xQNsutcwmWMML
8iUUTrSJs6RoH3AUl0qkYcTY+fU2sV+O/lKauMHF39aN2pgUVVo6Ncf9ki6Pp6eU
atb6b1sDCvylpG5pVME0T0CdOozlYZn+/+QSiia4pDLrC7+XEEPzxqZIM59Zk+eC
GoO8RSdBv7CSl9kzscaGibCOyknhWdsGqWmyf8eQm8zY3a7B3PiV1zXMe2RTlz/A
ouWyDfTt48bgrKKxd0rPhWaLFJ65r9Op+vRKaTZYucHu8YcphEyYG6QQ3qXEPD0c
r4OPYSKyMiiBMLW4z1912DW8F61fea+d28c2N6vQqaQRmtz9DLOpy/AWeUPt/N9a
wgJo2QHAuQENBF7pY2YBCACzlOgu8keGPzEEVU0JjXfzRNYXS44ER1HRSNlecb0r
q7e0EIttOVYvsYFbWLmagDRHDsoHn2/44jJczA0l/1OGq1vQmASEE5uKMbIfMIs4
tuHRP6E59JTJZ0Odlm9mB/rdJGA/HXArpoU5UHZycXnobkaq/707cfUgiPv+k7MW
DxGVigbBmupMJYX1rR1et0mBQmmfyM5/KwC3QP6EX6iXloROXgKL9VuNOPq6qWEq
pbROzZNEJ87cTX+oxhE4/kneeoGKYFN0iEZwC2f4JMim6unhuioGYXnlgJu7xWWU
wK1HdcRjZmIrmKLLLMVyrLmdvV/ATjv44RzQZbHSN3WrABEBAAGJATwEGAEIACYW
IQQcY2J1hLONjj3iV8OXpiXG2MfI9gUCXuljZgIbDAUJA8IaSgAKCRCXpiXG2MfI
9mx3CACeV2+EKqkh/KH/Q7eepAnQwfpt8SKNCzaUDfLxkvGWi9imZO7VRvmD/zv8
6PCPXuiwkVkfvS3Ia6u5/zJDozywy8e/g03lOdxxoIC1vF4e49I8xk6m9OuR/hRY
kRlixrF3gcONStsRmFE46u7VA+43NNLpcnu8IrsmmHF4zF0ZCwDLx+CXTPvqbEWe
+HvrUKf2itJ6JS7GwIPR/oWKKBmKSk+Xp7BPom3R3SK0AQYn++qku5BeV/yHy3s+
PswrP0kho9JfMxnq+89xEgNaQGJdUgOWi7bjQx8VxAdvPES5lmAeDAvBjAiXSg18
Kt6n86nWIMcKGGi444MyACNA3Aqj
=wRb+
-----END PGP PUBLIC KEY BLOCK-----
TEXT;

            public function getPrivateKeySourceText() : string {
                return self::$privateKeySourceText;
            }

            public function getPublicKeySourceText() : string {
                return self::$publicKeySourceText;
            }
        };
    }

    /**
     * @return string
     */
    protected static function getX509CertificateSourceText() : string {
        return <<<TEXT
-----BEGIN CERTIFICATE-----

MIIDvDCCAqQCCQCZovg3nWlgVDANBgkqhkiG9w0BAQsFADCBnzELMAkGA1UEBhMC
SUUxDTALBgNVBAgMBENvcmsxDTALBgNVBAcMBENvcmsxGTAXBgNVBAoMEE1pbmRU
b3VjaERhcnJhZ2gxEDAOBgNVBAsMB1N1cHBvcnQxHjAcBgNVBAMMFWRhcnJhZ2hz
Lm1pbmR0b3VjaC51czElMCMGCSqGSIb3DQEJARYWZGFycmFnaHNAbWluZHRvdWNo
LmNvbTAeFw0xOTAzMTQxMDUwNDJaFw0yMDAzMTMxMDUwNDJaMIGfMQswCQYDVQQG
EwJJRTENMAsGA1UECAwEQ29yazENMAsGA1UEBwwEQ29yazEZMBcGA1UECgwQTWlu
ZFRvdWNoRGFycmFnaDEQMA4GA1UECwwHU3VwcG9ydDEeMBwGA1UEAwwVZGFycmFn
aHMubWluZHRvdWNoLnVzMSUwIwYJKoZIhvcNAQkBFhZkYXJyYWdoc0BtaW5kdG91
Y2guY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn5Jt/AmA9VdU
4O8iEGrD7xmPPe5pvgCmop9/W/lsrr+m7UCjklbb8cjxriKwrlrhJBZPFlETJAiq
y7u4Jbzr1cluMwO3Z8kBBlwb4mhvTgu9ZPpCA/V3FTVeNz/yOiWbNhi2YmTunozV
Zy3L2iBWoBz/JSlvG0ktoDm5uMREw49XTiwujKufzzU6Dbvs7MMTodIY7BbzedEL
Oz8tyr92ymiQbUGW9kkxAPWQZC8+h2uNCQDNY7EvUVT5qD2Q89RdGEG4ZeYnv8Vs
ULEbD6ZYW5lNa3HnzoKjtVIZuaBbT8sdWB8G/w8gkvScAgcdl/cR7ix2y7kTYbSm
TsBotLfsgQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAYytRVlEuO3bSY/y63cAHh
ioq6YrYM9LrPEY4S3lIuULEniGqwHt/RlCaAk5GA3fsn+Z9Sh55eS3TsLyEmDpuX
XyjZludpuh8AcVItpQKamkSycgMnlpx/yNg5yThRY1PYctDDwN+N+WbR8cwws8dt
RwV7jW53jJEPK0dX/Rd8Uc1753csrT6ZXZDUMg/jpSaqw1hKuVYTDgkxM8NJJHbA
prmdEeunjNGwsxyhk1HAHY4SLtTMfHylGfniebrf2r8VvxD1McOAhnWq9U67nbte
mcCzFF4TSb7cIbuqFW8gzcMrAWJOKnVwIARCNaE3rlfZ5h1mxI8/Rdoa+WgFsqXi

-----END CERTIFICATE-----
TEXT;
    }
}
