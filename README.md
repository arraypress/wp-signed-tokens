# WordPress Signed Tokens

Tokens you can put in a URL that expire, cannot be forged, and cannot be reused
somewhere else.

## What it does

A download link, a magic sign-in, an unsubscribe URL — all the same shape. Put
something in a URL, and later trust that you put it there and that it has not
expired.

Doing it by hand usually means an `md5()` of some values and a database row to
check against. This signs the payload with HMAC instead, so there is nothing to
look up, and compares in constant time so the signature cannot be guessed a
byte at a time.

The namespace is the part people leave out: a token signed for `download` will
not verify as a token for `login`, even with the same secret.

## Features

- Sign a payload into a compact, URL-safe token
- Namespaced, so a token for one purpose cannot be replayed at another
- Expires on its own — no cleanup job, no database row
- Constant-time comparison, so signatures cannot be brute-forced by timing
- Derives its secret from the site's own salts, or takes one you supply
- Tells you *why* a token failed — expired, wrong namespace, tampered with
- Detached signatures, for when the payload travels separately

## Installation

```bash
composer require arraypress/wp-signed-tokens
```

## Quick start

```php
use ArrayPress\SignedTokens\Secret;

$signer = Secret::signer();

// A download link good for an hour.
$token = $signer->sign( 'download', [ 'file_id' => 42, 'order' => 1001 ], HOUR_IN_SECONDS );
$url   = add_query_arg( 'token', $token, home_url( '/download/' ) );

// On the way back in.
$verified = $signer->verify( 'download', $_GET['token'] ?? '' );

if ( ! $verified ) {
    wp_die( 'This link has expired.' );
}

$file_id = $verified->int( 'file_id' );
```

## Requirements

* PHP 8.3 or later
* WordPress 7.1 or later

## License

GPL-2.0-or-later
