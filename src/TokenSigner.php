<?php
/**
 * HMAC-signed, expiring, namespaced tokens for URLs.
 *
 * @package   ArrayPress\SignedTokens
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace ArrayPress\SignedTokens;

/**
 * Class TokenSigner
 *
 * Stateless tokens for links you email people: magic sign-in, password
 * reset, download URLs, unsubscribe, abandoned-cart resume. The token
 * carries its own claims and expiry and needs no database row.
 *
 * Typical use:
 *
 *   $signer = new TokenSigner( $secret );
 *
 *   $token = $signer->sign( 'magic-link', [ 'user' => 42 ], 900 );
 *   $url   = 'https://example.com/login/' . $token;
 *
 *   $result = $signer->inspect( 'magic-link', $token );
 *
 *   if ( $result instanceof Token ) {
 *       $user_id = $result->int( 'user' );
 *   } else {
 *       echo $result->public_message();
 *   }
 *
 * Three design decisions worth knowing:
 *
 * **Namespaces are mandatory and are not stored in the token.** They are
 * mixed into the signature instead, so a token minted for `password-reset`
 * cannot be replayed against `magic-link` even though both carry a user
 * id. An attacker cannot see or influence the namespace, only guess it.
 *
 * **Secrets rotate without invalidating live links.** Pass retired
 * secrets as `$previous`: signing always uses the current secret, while
 * verification accepts any of them. Emailed links keep working through a
 * rotation, which is what makes rotating feasible at all.
 *
 * **Tokens are not revocable and not single-use.** That is the trade for
 * needing no storage. Anyone holding the token can use it repeatedly
 * until it expires. Where that matters — password resets especially —
 * keep a nonce in the payload and record it as spent on first use:
 *
 *   $token = $signer->sign( 'reset', [ 'user' => 42, 'n' => bin2hex( random_bytes( 8 ) ) ], 900 );
 *
 * Then reject any token whose `n` you have already seen. Keep expiries
 * short regardless.
 *
 * @since 1.0.0
 */
final readonly class TokenSigner {

	/**
	 * Shortest secret accepted, in bytes.
	 *
	 * Below this, an offline attacker can brute-force the secret from a
	 * single captured token and then mint whatever they like.
	 */
	public const MIN_SECRET_BYTES = 32;

	/**
	 * Hash used for the signature and the key derivation.
	 */
	private const ALGORITHM = 'sha256';

	/**
	 * Domain-separation context for per-namespace subkey derivation.
	 *
	 * Versioned: bumping this invalidates every token in circulation, so
	 * it moves only on a deliberate format break.
	 */
	private const KDF_CONTEXT = 'arraypress/wp-signed-tokens/v1/';

	/**
	 * Signature length in hex characters.
	 */
	private const SIGNATURE_LENGTH = 64;

	/**
	 * Retired secrets still accepted at verification.
	 *
	 * @var string[]
	 */
	private array $previous;

	/**
	 * @since 1.0.0
	 *
	 * @param string   $secret    Current signing secret. At least
	 *                            {@see self::MIN_SECRET_BYTES} bytes;
	 *                            `bin2hex( random_bytes( 32 ) )` is ideal.
	 * @param string[] $previous  Retired secrets, accepted for
	 *                            verification only, so live links survive
	 *                            a rotation.
	 * @param int|null $timestamp Fixed Unix time, for tests. Null uses
	 *                            the clock.
	 *
	 * @throws \InvalidArgumentException When the secret is too short.
	 */
	public function __construct(
		#[\SensitiveParameter]
		private string $secret,
		#[\SensitiveParameter]
		array $previous = array(),
		private ?int $timestamp = null,
	) {
		if ( strlen( $secret ) < self::MIN_SECRET_BYTES ) {
			throw new \InvalidArgumentException(
				'Signing secret must be at least ' . self::MIN_SECRET_BYTES . ' bytes. '
				. 'Generate one with bin2hex( random_bytes( 32 ) ).'
			);
		}

		$this->previous = array_values( array_filter( $previous, static fn( $s ): bool => is_string( $s ) && '' !== $s ) );
	}

	/* ─── Signing ───────────────────────────────────────────────────── */

	/**
	 * Mint a token.
	 *
	 * @since 1.0.0
	 *
	 * @param string                         $namespace What the token is for,
	 *                                                  e.g. `magic-link`.
	 *                                                  Letters, digits, `-`,
	 *                                                  `_` and `.`, up to 64
	 *                                                  characters.
	 * @param array<string, string|int|bool> $payload   Claims. Scalars only —
	 *                                                  keep it small, this ends
	 *                                                  up in a URL.
	 * @param int                            $ttl       Lifetime in seconds
	 *                                                  from now.
	 *
	 * @return string URL-safe token.
	 *
	 * @throws \InvalidArgumentException On a bad namespace, non-scalar
	 *                                   payload value, or non-positive TTL.
	 */
	public function sign( string $namespace, array $payload, int $ttl ): string {
		if ( $ttl < 1 ) {
			throw new \InvalidArgumentException( 'Token TTL must be at least 1 second.' );
		}

		return $this->sign_until( $namespace, $payload, $this->now() + $ttl );
	}

	/**
	 * Mint a token that expires at a specific time.
	 *
	 * @since 1.0.0
	 *
	 * @param string                         $namespace  Token purpose.
	 * @param array<string, string|int|bool> $payload    Claims.
	 * @param int                            $expires_at Unix timestamp.
	 *
	 * @return string URL-safe token.
	 *
	 * @throws \InvalidArgumentException On a bad namespace or payload.
	 */
	public function sign_until( string $namespace, array $payload, int $expires_at ): string {
		$namespace = self::assert_namespace( $namespace );
		$encoded   = Base64Url::encode( self::encode_payload( $payload ) );

		return $encoded . '.' . $expires_at . '.' . $this->signature( $namespace, $encoded, $expires_at, $this->secret );
	}

	/* ─── Verification ──────────────────────────────────────────────── */

	/**
	 * Verify a token.
	 *
	 * @since 1.0.0
	 *
	 * @param string $namespace Purpose the token must have been signed for.
	 * @param string $token     Token from the URL.
	 *
	 * @return Token|null Verified contents, or null on any failure.
	 */
	public function verify( string $namespace, string $token ): ?Token {
		$result = $this->inspect( $namespace, $token );

		return $result instanceof Token ? $result : null;
	}

	/**
	 * Verify a token, reporting why it failed.
	 *
	 * Use this where the distinction matters to the user — an expired
	 * magic link deserves "request a new one", not "invalid link".
	 *
	 * The signature is always checked before the expiry, so a forged
	 * token can never come back as {@see Reason::Expired}.
	 *
	 * @since 1.0.0
	 *
	 * @param string $namespace Purpose the token must have been signed for.
	 * @param string $token     Token from the URL.
	 *
	 * @return Token|Reason Verified contents, or why not.
	 */
	public function inspect( string $namespace, string $token ): Token|Reason {
		$namespace = self::assert_namespace( $namespace );
		$parts     = explode( '.', $token );

		if ( 3 !== count( $parts ) ) {
			return Reason::Malformed;
		}

		[ $encoded, $expiry_raw, $given ] = $parts;

		if ( 1 !== preg_match( '/^\d{1,20}$/', $expiry_raw ) ) {
			return Reason::Malformed;
		}

		if ( strlen( $given ) !== self::SIGNATURE_LENGTH || 1 !== preg_match( '/^[a-f0-9]+$/', $given ) ) {
			return Reason::Malformed;
		}

		$expires_at = (int) $expiry_raw;
		$matched    = false;

		// Every known secret is checked, without early exit, so the time
		// taken never reveals which one matched or how many are held.
		foreach ( array_merge( array( $this->secret ), $this->previous ) as $candidate ) {
			if ( hash_equals( $this->signature( $namespace, $encoded, $expires_at, $candidate ), $given ) ) {
				$matched = true;
			}
		}

		if ( ! $matched ) {
			return Reason::InvalidSignature;
		}

		$raw = Base64Url::decode( $encoded );

		if ( false === $raw ) {
			return Reason::Malformed;
		}

		$payload = self::decode_payload( $raw );

		if ( null === $payload ) {
			return Reason::Malformed;
		}

		// Expiry is checked last, so this outcome is only ever reported
		// for a token we genuinely issued.
		if ( $expires_at <= $this->now() ) {
			return Reason::Expired;
		}

		return new Token( $namespace, $payload, $expires_at );
	}

	/* ─── Detached signatures ───────────────────────────────────────── */

	/**
	 * Sign values that travel separately from the signature.
	 *
	 * For URLs that already carry their parameters and just need
	 * authenticating — `/download?c=1&p=2&f=0&exp=…&sig=…`. Prefer
	 * {@see self::sign()} for anything new; this exists so existing URL
	 * shapes can be kept.
	 *
	 * @since 1.0.0
	 *
	 * @param string                         $namespace  Token purpose.
	 * @param array<string, string|int|bool> $payload    Values being signed.
	 * @param int                            $expires_at Unix timestamp.
	 *
	 * @return string 64-character hex signature.
	 *
	 * @throws \InvalidArgumentException On a bad namespace or payload.
	 */
	public function sign_detached( string $namespace, array $payload, int $expires_at ): string {
		return $this->signature(
			self::assert_namespace( $namespace ),
			Base64Url::encode( self::encode_payload( $payload ) ),
			$expires_at,
			$this->secret
		);
	}

	/**
	 * Verify a detached signature.
	 *
	 * @since 1.0.0
	 *
	 * @param string                         $namespace  Token purpose.
	 * @param array<string, string|int|bool> $payload    Values as received.
	 * @param int                            $expires_at Expiry as received.
	 * @param string                         $given      Signature as received.
	 *
	 * @return bool
	 */
	public function verify_detached( string $namespace, array $payload, int $expires_at, string $given ): bool {
		if ( strlen( $given ) !== self::SIGNATURE_LENGTH || 1 !== preg_match( '/^[a-f0-9]+$/', $given ) ) {
			return false;
		}

		try {
			$namespace = self::assert_namespace( $namespace );
			$encoded   = Base64Url::encode( self::encode_payload( $payload ) );
		} catch ( \InvalidArgumentException ) {
			return false;
		}

		$matched = false;

		foreach ( array_merge( array( $this->secret ), $this->previous ) as $candidate ) {
			if ( hash_equals( $this->signature( $namespace, $encoded, $expires_at, $candidate ), $given ) ) {
				$matched = true;
			}
		}

		return $matched && $expires_at > $this->now();
	}

	/* ─── Internals ─────────────────────────────────────────────────── */

	/**
	 * Compute the signature for a token.
	 *
	 * The namespace is not signed directly. It is used to derive a
	 * per-purpose subkey from the master secret, and the token is signed
	 * with that. This is HMAC-based key derivation, and it is the modern
	 * form of what WordPress does by hand with eight separate
	 * `*_KEY`/`*_SALT` constants: every purpose gets independent key
	 * material, so a weakness in one cannot be carried across to
	 * another. Unlike the WordPress arrangement, you hold one secret and
	 * the subkeys are computed, so there is nothing extra to generate,
	 * store, or rotate.
	 *
	 * The derivation context is versioned. Changing it would invalidate
	 * every token in circulation, so it only moves on a deliberate
	 * format break.
	 *
	 * Payload and expiry are joined with `|`, which occurs in neither —
	 * the payload is base64url and the expiry is digits — so no two
	 * different tokens can produce the same signed string by shifting
	 * characters across the boundary.
	 *
	 * @since 1.0.0
	 *
	 * @param string $namespace  Validated namespace.
	 * @param string $encoded    Base64url payload.
	 * @param int    $expires_at Unix timestamp.
	 * @param string $secret     Master secret to derive from.
	 *
	 * @return string Hex digest.
	 */
	private function signature( string $namespace, string $encoded, int $expires_at, #[\SensitiveParameter] string $secret ): string {
		$subkey = hash_hmac( self::ALGORITHM, self::KDF_CONTEXT . $namespace, $secret, true );

		return hash_hmac( self::ALGORITHM, $encoded . '|' . $expires_at, $subkey );
	}

	/**
	 * Generate a master secret.
	 *
	 * Convenience for setup scripts. Store the result in your
	 * environment — the library never persists anything.
	 *
	 * @since 1.0.0
	 *
	 * @return string 64 hex characters (256 bits of entropy).
	 *
	 * @throws \Random\RandomException When the CSPRNG is unavailable.
	 */
	public static function generate_secret(): string {
		return bin2hex( random_bytes( 32 ) );
	}

	/**
	 * Validate a namespace.
	 *
	 * @since 1.0.0
	 *
	 * @param string $namespace Raw namespace.
	 *
	 * @return string Lowercased namespace.
	 *
	 * @throws \InvalidArgumentException When it contains anything else.
	 */
	private static function assert_namespace( string $namespace ): string {
		if ( 1 !== preg_match( '/^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$/', $namespace ) ) {
			throw new \InvalidArgumentException(
				'Token namespace must be 1-64 characters of letters, digits, hyphen, underscore or dot.'
			);
		}

		return strtolower( $namespace );
	}

	/**
	 * Serialise a payload, rejecting anything that would not survive the
	 * round trip.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, string|int|bool> $payload Claims.
	 *
	 * @return string JSON.
	 *
	 * @throws \InvalidArgumentException On a non-scalar value or a
	 *                                   non-string key.
	 */
	private static function encode_payload( array $payload ): string {
		foreach ( $payload as $key => $value ) {
			if ( ! is_string( $key ) ) {
				throw new \InvalidArgumentException( 'Token payload keys must be strings.' );
			}

			if ( ! is_string( $value ) && ! is_int( $value ) && ! is_bool( $value ) ) {
				throw new \InvalidArgumentException(
					'Token payload value for "' . $key . '" must be a string, int or bool. '
					. 'Tokens travel in URLs — keep them small and flat.'
				);
			}
		}

		// Sorted so the same claims always produce the same token.
		ksort( $payload );

		return json_encode( $payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES );
	}

	/**
	 * Parse a payload back.
	 *
	 * @since 1.0.0
	 *
	 * @param string $raw Decoded JSON.
	 *
	 * @return array<string, string|int|bool>|null Null when not a flat object.
	 */
	private static function decode_payload( string $raw ): ?array {
		try {
			$decoded = json_decode( $raw, true, 4, JSON_THROW_ON_ERROR );
		} catch ( \JsonException ) {
			return null;
		}

		if ( ! is_array( $decoded ) ) {
			return null;
		}

		foreach ( $decoded as $key => $value ) {
			if ( ! is_string( $key ) || ( ! is_string( $value ) && ! is_int( $value ) && ! is_bool( $value ) ) ) {
				return null;
			}
		}

		return $decoded;
	}

	/**
	 * Current time, honouring the fixed timestamp when set.
	 *
	 * @since 1.0.0
	 *
	 * @return int
	 */
	private function now(): int {
		return $this->timestamp ?? time();
	}
}
