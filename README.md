# miniflex

![miniflex](docs/miniflex.jpg)*Source: [Crypto Museum](https://www.cryptomuseum.com/crypto/philips/miniflex/index.htm)*

---

A collection of PHP components to manage cryptographic keys and signatures

[![github.com](https://github.com/modethirteen/miniflex/workflows/build/badge.svg)](https://github.com/modethirteen/miniflex/actions?query=workflow%3Abuild)
[![codecov.io](https://codecov.io/github/modethirteen/miniflex/coverage.svg?branch=main)](https://codecov.io/github/modethirteen/miniflex?branch=main)
[![Latest Stable Version](https://poser.pugx.org/modethirteen/miniflex/version.svg)](https://packagist.org/packages/modethirteen/miniflex)
[![Latest Unstable Version](https://poser.pugx.org/modethirteen/miniflex/v/unstable)](https://packagist.org/packages/modethirteen/miniflex)

## Requirements

* PHP 7.2, 7.3, 7.4 (main, 1.x)

## Installation

Use [Composer](https://getcomposer.org/). There are two ways to add miniflex to your project.

From the composer CLI:

```sh
./composer.phar require modethirteen/miniflex
```

Or add modethirteen/miniflex to your project's composer.json:

```json
{
    "require": {
        "modethirteen/miniflex": "dev-main"
    }
}
```

`dev-main` is the main development branch. If you are using miniflex in a production environment, it is advised that you use a stable release.

Assuming you have setup Composer's autoloader, miniflex can be found in the `modethirteen\Crypto\` namespace.
