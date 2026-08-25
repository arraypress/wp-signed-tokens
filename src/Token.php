<?php
/**
 * A verified token's contents.
 *
 * @package   ArrayPress\SignedTokens
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace ArrayPress\SignedTokens;

/**
 * Class Token
 *
 * Only ever constructed by {@see TokenSigner} after a signature has been
 * verified, so holding one of these means the payload is authentic — it
 * came from something holding your secret and has not been altered.
 *
 * It does **not** mean the token is unused. These are stateless; see
 * {@see TokenSigner} on single-use handling.
 *
 * @since 1.0.0
 */
final readonly class Token {

	/**
	 * @since 1.0.0
	 *
	 * @param string                         $namespace  Purpose the token was verified under.
	 * @param array<string, string|int|bool> $payload    Verified claims.
	 * @param int                            $expires_at Unix timestamp.
	 */
	public function __construct(
		public string $namespace,
		public array $payload,
		public int $expires_at,
	) {}

	/**
	 * Read a single claim.
	 *
	 * @since 1.0.0
	 *
	 * @param string                     $key     Claim name.
	 * @param string|int|bool|null       $default Returned when absent.
	 *
	 * @return string|int|bool|null
	 */
	public function get( string $key, string|int|bool|null $default = null ): string|int|bool|null {
		return $this->payload[ $key ] ?? $default;
	}

	/**
	 * Read a claim as an integer — the common case, since most payloads
	 * are row ids.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key     Claim name.
	 * @param int    $default Returned when absent or non-numeric.
	 *
	 * @return int
	 */
	public function int( string $key, int $default = 0 ): int {
		$value = $this->payload[ $key ] ?? null;

		return is_int( $value ) || ( is_string( $value ) && 1 === preg_match( '/^-?\d+$/', $value ) )
			? (int) $value
			: $default;
	}

	/**
	 * Whether a claim is present.
	 *
	 * @since 1.0.0
	 *
	 * @param string $key Claim name.
	 *
	 * @return bool
	 */
	public function has( string $key ): bool {
		return array_key_exists( $key, $this->payload );
	}

	/**
	 * Seconds of validity left.
	 *
	 * @since 1.0.0
	 *
	 * @param int|null $now Unix time to measure against. Null uses the clock.
	 *
	 * @return int Never negative — a verified token has not expired.
	 */
	public function seconds_remaining( ?int $now = null ): int {
		return max( 0, $this->expires_at - ( $now ?? time() ) );
	}
}
