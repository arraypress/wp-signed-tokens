<?php
/**
 * Base64Url test suite.
 *
 * @package   ArrayPress\SignedTokens
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace ArrayPress\SignedTokens\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ArrayPress\SignedTokens\Base64Url;

final class Base64UrlTest extends TestCase {

	#[DataProvider( 'round_trip_lengths' )]
	public function test_binary_round_trips_at_every_padding_offset( int $length ): void {
		$raw = random_bytes( $length );

		$this->assertSame( $raw, Base64Url::decode( Base64Url::encode( $raw ) ) );
	}

	/** @return array<string, array{0: int}> */
	public static function round_trip_lengths(): array {
		$out = array();

		for ( $i = 1; $i <= 12; $i++ ) {
			$out[ $i . ' bytes' ] = array( $i );
		}

		return $out;
	}

	public function test_output_is_unpadded(): void {
		$this->assertStringNotContainsString( '=', Base64Url::encode( 'f' ) );
	}

	public function test_output_uses_the_url_safe_alphabet(): void {
		// 0xFB 0xFF encodes to '+/' territory under standard base64.
		$encoded = Base64Url::encode( "\xFB\xFF\xBF" );

		$this->assertStringNotContainsString( '+', $encoded );
		$this->assertStringNotContainsString( '/', $encoded );
	}

	public function test_output_survives_url_encoding_untouched(): void {
		$encoded = Base64Url::encode( random_bytes( 64 ) );

		$this->assertSame( $encoded, rawurlencode( $encoded ) );
	}

	public function test_unicode_round_trips(): void {
		$raw = '日本語 café 🎵';

		$this->assertSame( $raw, Base64Url::decode( Base64Url::encode( $raw ) ) );
	}

	#[DataProvider( 'invalid_input' )]
	public function test_invalid_input_is_rejected( string $input ): void {
		$this->assertFalse( Base64Url::decode( $input ) );
	}

	/** @return array<string, array{0: string}> */
	public static function invalid_input(): array {
		return array(
			'empty'            => array( '' ),
			'standard plus'    => array( 'ab+c' ),
			'standard slash'   => array( 'ab/c' ),
			'padding'          => array( 'YQ==' ),
			'space'            => array( 'ab c' ),
			'orphan character' => array( 'abcde' ),
			'punctuation'      => array( 'ab.c' ),
			'unicode'          => array( 'abcé' ),
		);
	}

	public function test_encoding_is_deterministic(): void {
		$this->assertSame( Base64Url::encode( 'hello' ), Base64Url::encode( 'hello' ) );
	}
}
