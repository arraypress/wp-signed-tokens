# WP Signed Tokens

HMAC-signed, expiring, namespaced tokens for URLs. Magic sign-in links, password resets, download URLs, unsubscribe links — carrying their own claims and expiry, with no database row.

Zero dependencies. Not JWT: no algorithm negotiation, no `alg: none`, no header parsing, and nothing an attacker can influence about how the token is verified.

## Features

- 🔗 **URL-safe** — unpadded base64url; survives emails, redirects and copy-paste untouched.
- 🏷️ **Mandatory namespaces** — a password-reset token can't be replayed as a magic link, even with identical claims.
- 🔄 **Secret rotation** — retire a secret without invalidating links already in inboxes.
- ⏰ **Expiry built in** — signed, so it can't be extended.
- 💬 **Actionable failures** — distinguish "expired" from "invalid" for user-facing messaging, without leaking to attackers.
- 🛡️ **Constant-time** — `hash_equals`, and every known secret checked without early exit.
- ✍️ **Detached mode** — sign parameters that travel separately, for existing URL shapes.


## WordPress: where the secret comes from

You do not have to store one. `Secret::signer()` derives a key from the site's
own salts, which every install has and which are not in the database:

```php
use ArrayPress\\SignedTokens\\Secret;

$signer = Secret::signer( 'downloads' );

$token = $signer->sign( 'file', [ 'file' => 128, 'order' => 4471 ], 900 );
$url   = home_url( '/download/' . $token );
```

The `purpose` argument keys the signer separately, so your plugin does not
share a key with the site or with another plugin that had the same idea. A
token signed for `downloads` will not verify under `magic-link`.

Two consequences worth knowing:

- **Rotating the site's salts invalidates every token.** That is correct
  rather than unfortunate — rotating the salts is how WordPress says "log
  everybody out", and a download link that survived it would be a link that
  survived the revocation.
- **A site still on the placeholder salts is refused**, loudly. Signing every
  token in an installation with a string printed in the documentation is worse
  than not signing at all.

Pass your own secret to `TokenSigner` directly if you would rather manage one,
including for rotation — see below.

## Requirements

PHP 8.3+ and WordPress

## Installation

```bash
composer require arraypress/wp-signed-tokens
```

## Usage

### Magic sign-in link

```php
use ArrayPress\SignedTokens\TokenSigner;

$signer = new TokenSigner( getenv( 'TOKEN_SECRET' ) );

$token = $signer->sign( 'magic-link', [ 'user' => 42 ], 900 );   // 15 minutes
$url   = 'https://example.com/login/' . $token;
```

Verifying:

```php
$token = $signer->verify( 'magic-link', $_GET['token'] ?? '' );

if ( null === $token ) {
    // invalid, tampered, or expired
}

$user_id = $token->int( 'user' );
```

### Telling the user what went wrong

`verify()` collapses every failure to null. When the difference matters — an expired magic link deserves "request a new one", not "invalid link" — use `inspect()`:

```php
use ArrayPress\SignedTokens\{Token, Reason};

$result = $signer->inspect( 'magic-link', $input );

if ( $result instanceof Token ) {
    log_in( $result->int( 'user' ) );
} else {
    echo $result->public_message();
}
```

The signature is always checked **before** the expiry, so a forged token comes back as `InvalidSignature` and never `Expired`. Nothing in the response tells an attacker they got the structure right.

### Namespaces

The namespace is mandatory and is **not stored in the token** — it's mixed into the signature. A token signed for one purpose can't be verified as another, even with identical claims, and an attacker can't see or influence it:

```php
$reset = $signer->sign( 'password-reset', [ 'user' => 42 ], 900 );

$signer->verify( 'magic-link', $reset );   // null
```

### Secret rotation

Signing always uses the current secret; verification accepts retired ones too. Links already sitting in inboxes keep working, which is what makes rotating practical at all:

```php
$signer = new TokenSigner(
    secret:   getenv( 'TOKEN_SECRET' ),
    previous: [ getenv( 'TOKEN_SECRET_OLD' ) ],
);
```

Drop the old secret once its longest TTL has passed.

### Single use

**Tokens are stateless, so they are not revocable and not single-use.** That's the trade for needing no storage — anyone holding the token can use it repeatedly until it expires.

Where that matters (password resets especially), put a nonce in the payload and record it as spent:

```php
$token = $signer->sign( 'reset', [
    'user' => 42,
    'n'    => bin2hex( random_bytes( 8 ) ),
], 900 );

// On use:
if ( $store->already_seen( $verified->get( 'n' ) ) ) {
    // reject
}
```

Keep expiries short regardless. Fifteen minutes for sign-in, an hour for downloads.

### Detached signatures

For URLs that already carry their parameters and just need authenticating:

```php
$signature = $signer->sign_detached( 'download', [
    'customer' => 1,
    'product'  => 2,
    'file'     => 0,
], $expires_at );

// /download?customer=1&product=2&file=0&exp=…&sig=…

$ok = $signer->verify_detached( 'download', $params, $expires_at, $_GET['sig'] );
```

Prefer `sign()` for anything new — this exists so existing URL shapes can be preserved.

### Payload rules

Claims must be flat scalars (`string`, `int`, `bool`). Nested arrays, objects, floats and nulls are rejected at signing time rather than silently mangled. Tokens go in URLs — keep them small.

Claim order doesn't affect the token; keys are sorted before signing.

### Secrets

At least 32 bytes, enforced:

```bash
php -r "echo bin2hex(random_bytes(32));"
```

## Why not JWT?

JWT carries its own algorithm in an attacker-supplied header, which has produced a long run of `alg: none` and RS256/HS256 confusion vulnerabilities. Here the algorithm is fixed, the namespace is chosen by the verifying code rather than the token, and there's no header to parse. Less flexible, and that's the point.

If you need interop with something that expects JWT, use JWT. If you're signing your own links, this is a smaller target.

## Testing

```bash
composer install
composer test
```

95 tests, covering tamper detection, cross-namespace replay, expiry boundaries, rotation, and failure-precedence ordering.

## License

GPL-2.0-or-later
