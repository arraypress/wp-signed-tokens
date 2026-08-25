<?php
/**
 * Ttl test suite.
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
use ArrayPress\SignedTokens\TokenSigner;
use ArrayPress\SignedTokens\Ttl;

final class TtlTest extends TestCase {

	#[DataProvider( 'constants' )]
	public function test_constants_are_correct( int $actual, int $expected ): void {
		$this->assertSame( $expected, $actual );
	}

	/** @return array<string, array{0: int, 1: int}> */
	public static function constants(): array {
		return array(
			'minute'          => array( Ttl::MINUTE, 60 ),
			'five minutes'    => array( Ttl::FIVE_MINUTES, 5 * 60 ),
			'ten minutes'     => array( Ttl::TEN_MINUTES, 10 * 60 ),
			'fifteen minutes' => array( Ttl::FIFTEEN_MINUTES, 15 * 60 ),
			'thirty minutes'  => array( Ttl::THIRTY_MINUTES, 30 * 60 ),
			'hour'            => array( Ttl::HOUR, 60 * 60 ),
			'two hours'       => array( Ttl::TWO_HOURS, 2 * 60 * 60 ),
			'six hours'       => array( Ttl::SIX_HOURS, 6 * 60 * 60 ),
			'twelve hours'    => array( Ttl::TWELVE_HOURS, 12 * 60 * 60 ),
			'day'             => array( Ttl::DAY, 24 * 60 * 60 ),
			'three days'      => array( Ttl::THREE_DAYS, 3 * 24 * 60 * 60 ),
			'week'            => array( Ttl::WEEK, 7 * 24 * 60 * 60 ),
			'thirty days'     => array( Ttl::THIRTY_DAYS, 30 * 24 * 60 * 60 ),
			'year'            => array( Ttl::YEAR, 365 * 24 * 60 * 60 ),
		);
	}

	public function test_factories_agree_with_the_constants(): void {
		$this->assertSame( Ttl::FIFTEEN_MINUTES, Ttl::minutes( 15 ) );
		$this->assertSame( Ttl::TWO_HOURS, Ttl::hours( 2 ) );
		$this->assertSame( Ttl::THREE_DAYS, Ttl::days( 3 ) );
		$this->assertSame( Ttl::WEEK, Ttl::weeks( 1 ) );
		$this->assertSame( Ttl::THIRTY_DAYS, Ttl::days( 30 ) );
	}

	public function test_a_ttl_constant_signs_a_usable_token(): void {
		$now    = 1700000000;
		$signer = new TokenSigner( TokenSigner::generate_secret(), array(), $now );
		$token  = $signer->verify( 'ns', $signer->sign( 'ns', array( 'u' => 1 ), Ttl::FIFTEEN_MINUTES ) );

		$this->assertNotNull( $token );
		$this->assertSame( $now + 900, $token->expires_at );
	}
}
