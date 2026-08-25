<?php
/**
 * URL-safe base64 (RFC 4648 section 5).
 *
 * @package   ArrayPress\SignedTokens
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace ArrayPress\SignedTokens;

/**
 * Class Base64Url
 *
 * Standard base64 uses `+`, `/` and `=`, all of which need escaping in a
 * URL and none of which survive being pasted out of an email client
 * intact. This is the URL-safe alphabet, unpadded.
 *
 * @since 1.0.0
 */
final readonly class Base64Url {

	/**
	 * Encode raw bytes, unpadded.
	 *
	 * @since 1.0.0
	 *
	 * @param string $bytes Raw binary.
	 *
	 * @return string
	 */
	public static function encode( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}

	/**
	 * Decode, restoring padding.
	 *
	 * Strict: input containing characters outside the URL-safe alphabet
	 * is rejected rather than silently ignored, so a tampered token can
	 * never decode to something plausible.
	 *
	 * @since 1.0.0
	 *
	 * @param string $input Encoded text.
	 *
	 * @return string|false Raw bytes, or false when the input is not
	 *                      valid URL-safe base64.
	 */
	public static function decode( string $input ): string|false {
		if ( '' === $input || 1 !== preg_match( '/^[A-Za-z0-9\-_]+$/', $input ) ) {
			return false;
		}

		$padded = strtr( $input, '-_', '+/' );
		$remain = strlen( $padded ) % 4;

		if ( 1 === $remain ) {
			// No valid base64 encoding ever leaves one character over.
			return false;
		}

		if ( 0 !== $remain ) {
			$padded .= str_repeat( '=', 4 - $remain );
		}

		return base64_decode( $padded, true );
	}
}
