<?php
/**
 * Site-derived secret tests.
 *
 * @package ArrayPress\SignedTokens
 */

declare( strict_types=1 );

namespace ArrayPress\SignedTokens\Tests;

use ArrayPress\SignedTokens\Secret;
use ArrayPress\SignedTokens\TokenSigner;
use PHPUnit\Framework\TestCase;

/**
 * The one part of this library that is WordPress's rather than the signer's:
 * where the 32 bytes come from.
 *
 * A site already has somewhere sensible to get them -- the salts in
 * wp-config.php, which every install has and which are not in the database.
 * The care is in not handing a salt straight to the signer.
 */
final class SecretTest extends TestCase {

	/**
	 * Give the site a healthy salt.
	 */
	protected function setUp(): void {
		$GLOBALS['st_salt'] = str_repeat( 'k', 64 );
	}

	/**
	 * Put it back.
	 */
	protected function tearDown(): void {
		unset( $GLOBALS['st_salt'] );
	}

	/**
	 * A derived secret is long enough for the signer to accept.
	 */
	public function test_a_derived_secret_satisfies_the_signer(): void {
		$secret = Secret::from_salts();

		$this->assertGreaterThanOrEqual( TokenSigner::MIN_SECRET_BYTES, strlen( $secret ) );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{64}$/', $secret );
	}

	/**
	 * The salt is never the secret.
	 *
	 * wp_salt() hands the same value to every caller, so a token signed with
	 * it directly shares a key with session tokens and anything else that
	 * reaches for the same salt. A weakness in one would be a weakness in all
	 * of them.
	 */
	public function test_the_salt_is_not_used_as_the_secret(): void {
		$this->assertNotSame( $GLOBALS['st_salt'], Secret::from_salts() );
		$this->assertStringNotContainsString( $GLOBALS['st_salt'], Secret::from_salts() );
	}

	/**
	 * Two purposes give two unrelated keys.
	 *
	 * So a plugin does not have to share a signing key with the site, or with
	 * another plugin that had the same idea.
	 */
	public function test_each_purpose_gets_its_own_key(): void {
		$this->assertNotSame( Secret::from_salts( 'downloads' ), Secret::from_salts( 'magic-link' ) );
		$this->assertSame( Secret::from_salts( 'downloads' ), Secret::from_salts( 'downloads' ) );
	}

	/**
	 * A token signed for one purpose does not verify under another.
	 *
	 * The end-to-end version of the separation, through the signer rather than
	 * on the key itself.
	 */
	public function test_a_token_does_not_cross_between_purposes(): void {
		$token = Secret::signer( 'downloads' )->sign( 'file', array( 'id' => 7 ), 300 );

		$this->assertNotNull( Secret::signer( 'downloads' )->verify( 'file', $token ) );
		$this->assertNull( Secret::signer( 'magic-link' )->verify( 'file', $token ) );
	}

	/**
	 * Rotating the site's salts invalidates the tokens.
	 *
	 * Which is correct rather than unfortunate: rotating the salts is how a
	 * WordPress site says "log everybody out", and a download link that
	 * outlived it would be a link that survived the revocation.
	 */
	public function test_rotating_the_salts_invalidates_tokens(): void {
		$token = Secret::signer()->sign( 'file', array( 'id' => 7 ), 300 );

		$this->assertNotNull( Secret::signer()->verify( 'file', $token ) );

		$GLOBALS['st_salt'] = str_repeat( 'z', 64 );

		$this->assertNull( Secret::signer()->verify( 'file', $token ) );
	}

	/**
	 * A site with no real salt is refused rather than signed weakly.
	 *
	 * The failure mode this guards is the quiet one: an install whose
	 * wp-config still carries the placeholder would otherwise sign every
	 * token in the site with a string that is printed in the documentation.
	 *
	 * @param string $salt What the site has.
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider( 'uselessSaltProvider' )]
	public function test_a_site_without_a_real_salt_is_refused( string $salt ): void {
		$GLOBALS['st_salt'] = $salt;

		$this->expectException( \RuntimeException::class );

		Secret::from_salts();
	}

	/**
	 * @return array<string, array{0: string}>
	 */
	public static function uselessSaltProvider(): array {
		return array(
			'empty'           => array( '' ),
			'too short'       => array( 'abcdef' ),
			'the placeholder' => array( 'put your unique phrase here put your unique phrase here' ),
		);
	}
}
