<?php
/**
 * Where a WordPress site's signing secret comes from.
 *
 * @package   ArrayPress\SignedTokens
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace ArrayPress\SignedTokens;

/**
 * Class Secret
 *
 * The signer needs 32 bytes of secret and does not care where they come
 * from. On a WordPress site there is already somewhere sensible: the salts in
 * wp-config.php, which every install has and which are not in the database.
 *
 * This derives a per-purpose key from them rather than using a salt directly.
 * `wp_salt()` returns the same value to every caller, so handing it straight
 * to the signer would mean this library, a session token and anything else
 * reaching for the same salt were all keyed identically -- and a weakness in
 * one becomes a weakness in all of them. A derived subkey keeps them separate.
 *
 * @since 1.0.0
 */
final class Secret {

	/**
	 * Domain separation for the derived key.
	 *
	 * Versioned: changing it invalidates every token in circulation.
	 */
	private const CONTEXT = 'arraypress/wp-signed-tokens/secret/v1/';

	/**
	 * A signing secret derived from this site's salts.
	 *
	 * @since 1.0.0
	 *
	 * @param string $purpose What the key is for. Two callers passing
	 *                        different purposes get unrelated keys, so a
	 *                        plugin does not have to share one with the site.
	 *
	 * @return string 64 hex characters.
	 *
	 * @throws \RuntimeException When the site has no usable salt.
	 */
	public static function from_salts( string $purpose = 'default' ): string {
		$salt = wp_salt( 'auth' );

		// A site left on the placeholder salts, or one where wp-config was
		// generated without them, has nothing secret to derive from. Failing
		// loudly beats signing every token in the installation with the
		// string "put your unique phrase here".
		if ( strlen( $salt ) < 32 || str_contains( $salt, 'put your unique phrase here' ) ) {
			throw new \RuntimeException(
				'This site has no usable AUTH_SALT. Define the salts in wp-config.php '
				. '-- https://api.wordpress.org/secret-key/1.1/salt/ -- or pass a secret '
				. 'of your own to TokenSigner.'
			);
		}

		return hash_hmac( 'sha256', self::CONTEXT . $purpose, $salt );
	}

	/**
	 * A signer keyed to this site.
	 *
	 * The convenience most callers want: no secret to store, no rotation to
	 * arrange, and tokens that stop verifying if the site's salts are rotated
	 * -- which is the correct behaviour, because rotating the salts is how a
	 * WordPress site says "log everybody out".
	 *
	 * @since 1.0.0
	 *
	 * @param string $purpose What the key is for.
	 *
	 * @return TokenSigner
	 *
	 * @throws \RuntimeException When the site has no usable salt.
	 */
	public static function signer( string $purpose = 'default' ): TokenSigner {
		return new TokenSigner( self::from_salts( $purpose ) );
	}
}
