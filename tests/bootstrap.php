<?php
/**
 * PHPUnit bootstrap.
 *
 * @package ArrayPress\SignedTokens
 */

declare( strict_types=1 );

if ( ! function_exists( 'wp_salt' ) ) {
	/**
	 * Core's salt accessor.
	 *
	 * Returns whatever the test put in $GLOBALS['st_salt'], so a suite can
	 * exercise both a healthy site and one still on the placeholder salts.
	 *
	 * @param string $scheme Salt scheme.
	 *
	 * @return string
	 */
	function wp_salt( string $scheme = 'auth' ): string {
		return $GLOBALS['st_salt'] ?? str_repeat( 'a', 64 );
	}
}

require_once dirname( __DIR__ ) . '/vendor/autoload.php';
