<?php
/**
 * TokenSigner test suite.
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
use ArrayPress\SignedTokens\Reason;
use ArrayPress\SignedTokens\Token;
use ArrayPress\SignedTokens\TokenSigner;

final class TokenSignerTest extends TestCase {

	private const SECRET  = 'a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1';
	private const SECRET2 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
	private const NOW     = 1700000000;

	private function signer( ?int $now = self::NOW, array $previous = array() ): TokenSigner {
		return new TokenSigner( self::SECRET, $previous, $now );
	}

	/* ─── Round trip ────────────────────────────────────────────────── */

	public function test_a_signed_token_verifies(): void {
		$signer = $this->signer();
		$token  = $signer->sign( 'magic-link', array( 'user' => 42 ), 900 );

		$verified = $signer->verify( 'magic-link', $token );

		$this->assertInstanceOf( Token::class, $verified );
		$this->assertSame( 42, $verified->int( 'user' ) );
		$this->assertSame( self::NOW + 900, $verified->expires_at );
	}

	public function test_the_token_is_url_safe(): void {
		$token = $this->signer()->sign( 'ns', array( 'a' => 'x/y+z=', 'b' => 'ünïcödé' ), 60 );

		$this->assertSame( $token, rawurlencode( $token ) );
	}

	#[DataProvider( 'payload_values' )]
	public function test_scalar_claims_survive_the_round_trip( string|int|bool $value ): void {
		$signer = $this->signer();
		$token  = $signer->verify( 'ns', $signer->sign( 'ns', array( 'v' => $value ), 60 ) );

		$this->assertNotNull( $token );
		$this->assertSame( $value, $token->get( 'v' ) );
	}

	/** @return array<string, array{0: string|int|bool}> */
	public static function payload_values(): array {
		return array(
			'int'       => array( 42 ),
			'zero'      => array( 0 ),
			'negative'  => array( -7 ),
			'string'    => array( 'hello' ),
			'empty str' => array( '' ),
			'unicode'   => array( '日本語 café' ),
			'true'      => array( true ),
			'false'     => array( false ),
			'json-ish'  => array( '{"a":1}' ),
			'dots'      => array( 'a.b.c' ),
		);
	}

	public function test_claim_order_does_not_change_the_token(): void {
		$signer = $this->signer();

		$this->assertSame(
			$signer->sign_until( 'ns', array( 'a' => 1, 'b' => 2 ), self::NOW + 60 ),
			$signer->sign_until( 'ns', array( 'b' => 2, 'a' => 1 ), self::NOW + 60 )
		);
	}

	public function test_an_empty_payload_is_allowed(): void {
		$signer = $this->signer();

		$this->assertInstanceOf( Token::class, $signer->verify( 'ns', $signer->sign( 'ns', array(), 60 ) ) );
	}

	/* ─── Namespace isolation ───────────────────────────────────────── */

	public function test_a_token_will_not_verify_under_another_namespace(): void {
		$signer = $this->signer();
		$token  = $signer->sign( 'password-reset', array( 'user' => 42 ), 900 );

		$this->assertNull( $signer->verify( 'magic-link', $token ) );
	}

	public function test_cross_namespace_replay_reports_an_invalid_signature(): void {
		$signer = $this->signer();
		$token  = $signer->sign( 'password-reset', array( 'user' => 42 ), 900 );

		$this->assertSame( Reason::InvalidSignature, $signer->inspect( 'magic-link', $token ) );
	}

	public function test_namespaces_are_case_insensitive(): void {
		$signer = $this->signer();
		$token  = $signer->sign( 'Magic-Link', array( 'u' => 1 ), 60 );

		$this->assertInstanceOf( Token::class, $signer->verify( 'magic-link', $token ) );
	}

	public function test_the_namespace_is_not_present_in_the_token(): void {
		$token = $this->signer()->sign( 'super-secret-purpose', array( 'u' => 1 ), 60 );

		$this->assertStringNotContainsString( 'super-secret-purpose', $token );
		$this->assertStringNotContainsString( Base64Url::encode( 'super-secret-purpose' ), $token );
	}

	#[DataProvider( 'bad_namespaces' )]
	public function test_invalid_namespaces_are_rejected( string $namespace ): void {
		$this->expectException( \InvalidArgumentException::class );
		$this->signer()->sign( $namespace, array(), 60 );
	}

	/** @return array<string, array{0: string}> */
	public static function bad_namespaces(): array {
		return array(
			'empty'     => array( '' ),
			'pipe'      => array( 'a|b' ),
			'space'     => array( 'magic link' ),
			'slash'     => array( 'a/b' ),
			'newline'   => array( "a\nb" ),
			'leading .' => array( '.hidden' ),
			'too long'  => array( str_repeat( 'a', 65 ) ),
		);
	}

	/* ─── Tampering ─────────────────────────────────────────────────── */

	public function test_a_modified_payload_is_rejected(): void {
		$signer = $this->signer();
		$token  = $signer->sign( 'ns', array( 'user' => 42 ), 900 );

		[ , $expiry, $signature ] = explode( '.', $token );
		$forged                   = Base64Url::encode( '{"user":99}' ) . '.' . $expiry . '.' . $signature;

		$this->assertSame( Reason::InvalidSignature, $signer->inspect( 'ns', $forged ) );
	}

	public function test_an_extended_expiry_is_rejected(): void {
		$signer = $this->signer();
		$token  = $signer->sign( 'ns', array( 'user' => 42 ), 60 );

		[ $payload, , $signature ] = explode( '.', $token );
		$forged                    = $payload . '.' . ( self::NOW + 999999 ) . '.' . $signature;

		$this->assertSame( Reason::InvalidSignature, $signer->inspect( 'ns', $forged ) );
	}

	public function test_a_token_signed_with_another_secret_is_rejected(): void {
		$other = new TokenSigner( self::SECRET2, array(), self::NOW );
		$token = $other->sign( 'ns', array( 'user' => 42 ), 900 );

		$this->assertSame( Reason::InvalidSignature, $this->signer()->inspect( 'ns', $token ) );
	}

	public function test_flipping_a_single_signature_character_is_rejected(): void {
		$signer = $this->signer();
		$token  = $signer->sign( 'ns', array( 'u' => 1 ), 900 );

		$flipped         = substr( $token, 0, -1 ) . ( 'a' === substr( $token, -1 ) ? 'b' : 'a' );

		$this->assertSame( Reason::InvalidSignature, $signer->inspect( 'ns', $flipped ) );
	}

	#[DataProvider( 'malformed_tokens' )]
	public function test_malformed_tokens_are_reported_as_malformed( string $token ): void {
		$this->assertSame( Reason::Malformed, $this->signer()->inspect( 'ns', $token ) );
	}

	/** @return array<string, array{0: string}> */
	public static function malformed_tokens(): array {
		$sig = str_repeat( 'a', 64 );

		return array(
			'empty'            => array( '' ),
			'no dots'          => array( 'abc' ),
			'two segments'     => array( 'abc.123' ),
			'four segments'    => array( 'a.1.' . $sig . '.x' ),
			'short signature'  => array( 'YQ.123.' . str_repeat( 'a', 63 ) ),
			'uppercase sig'    => array( 'YQ.123.' . strtoupper( $sig ) ),
			'non-hex sig'      => array( 'YQ.123.' . str_repeat( 'z', 64 ) ),
			'negative expiry'  => array( 'YQ.-5.' . $sig ),
			'non-numeric exp'  => array( 'YQ.abc.' . $sig ),
		);
	}

	/**
	 * Structural problems in the payload are only reported once the
	 * signature has passed. An unsigned token with an empty payload is
	 * `InvalidSignature`, not `Malformed` — otherwise the response
	 * distinguishes "you got the shape wrong" from "you got the shape
	 * right but not the secret", which is information an attacker can
	 * use to iterate.
	 */
	public function test_signature_failure_takes_precedence_over_payload_shape(): void {
		$this->assertSame(
			Reason::InvalidSignature,
			$this->signer()->inspect( 'ns', '.123.' . str_repeat( 'a', 64 ) )
		);
	}

	public function test_an_empty_payload_segment_is_malformed_once_correctly_signed(): void {
		$signer     = $this->signer();
		$expiry     = self::NOW + 60;
		$reflection = new \ReflectionMethod( $signer, 'signature' );
		$signature  = $reflection->invoke( $signer, 'ns', '', $expiry, self::SECRET );

		$this->assertSame( Reason::Malformed, $signer->inspect( 'ns', '.' . $expiry . '.' . $signature ) );
	}

	public function test_a_payload_that_is_not_a_flat_object_is_rejected(): void {
		$signer = $this->signer();

		// Sign a legitimate token, then swap the payload for a nested one
		// and re-sign it with the same secret — proving the shape check
		// is independent of the signature check.
		$encoded = Base64Url::encode( '{"a":{"nested":1}}' );
		$expiry  = self::NOW + 60;

		$reflection = new \ReflectionMethod( $signer, 'signature' );
		$signature  = $reflection->invoke( $signer, 'ns', $encoded, $expiry, self::SECRET );

		$this->assertSame( Reason::Malformed, $signer->inspect( 'ns', $encoded . '.' . $expiry . '.' . $signature ) );
	}

	/* ─── Expiry ────────────────────────────────────────────────────── */

	public function test_an_expired_token_is_rejected(): void {
		$issuer = $this->signer();
		$token  = $issuer->sign( 'ns', array( 'u' => 1 ), 60 );

		$later = $this->signer( self::NOW + 61 );

		$this->assertNull( $later->verify( 'ns', $token ) );
		$this->assertSame( Reason::Expired, $later->inspect( 'ns', $token ) );
	}

	public function test_expiry_is_exclusive_at_the_boundary(): void {
		$token = $this->signer()->sign( 'ns', array( 'u' => 1 ), 60 );

		$this->assertInstanceOf( Token::class, $this->signer( self::NOW + 59 )->inspect( 'ns', $token ) );
		$this->assertSame( Reason::Expired, $this->signer( self::NOW + 60 )->inspect( 'ns', $token ) );
	}

	public function test_a_forged_expired_token_reports_a_bad_signature_not_expiry(): void {
		// An attacker must never learn that their forgery was otherwise
		// well-formed, so signature failure always wins over expiry.
		$forged = Base64Url::encode( '{"u":1}' ) . '.' . ( self::NOW - 100 ) . '.' . str_repeat( 'a', 64 );

		$this->assertSame( Reason::InvalidSignature, $this->signer()->inspect( 'ns', $forged ) );
	}

	public function test_seconds_remaining_counts_down(): void {
		$issuer = $this->signer();
		$token  = $issuer->sign( 'ns', array( 'u' => 1 ), 900 );

		$verified = $this->signer( self::NOW + 300 )->verify( 'ns', $token );

		$this->assertNotNull( $verified );
		$this->assertSame( 600, $verified->seconds_remaining( self::NOW + 300 ) );
	}

	public function test_a_non_positive_ttl_is_rejected(): void {
		$this->expectException( \InvalidArgumentException::class );
		$this->signer()->sign( 'ns', array(), 0 );
	}

	/* ─── Secret rotation ───────────────────────────────────────────── */

	public function test_a_token_signed_with_a_retired_secret_still_verifies(): void {
		$old   = new TokenSigner( self::SECRET2, array(), self::NOW );
		$token = $old->sign( 'ns', array( 'user' => 42 ), 900 );

		$rotated = new TokenSigner( self::SECRET, array( self::SECRET2 ), self::NOW );

		$this->assertInstanceOf( Token::class, $rotated->verify( 'ns', $token ) );
	}

	public function test_new_tokens_use_the_current_secret(): void {
		$rotated = new TokenSigner( self::SECRET, array( self::SECRET2 ), self::NOW );
		$current = new TokenSigner( self::SECRET, array(), self::NOW );

		$this->assertSame(
			$current->sign_until( 'ns', array( 'u' => 1 ), self::NOW + 60 ),
			$rotated->sign_until( 'ns', array( 'u' => 1 ), self::NOW + 60 )
		);
	}

	public function test_dropping_a_retired_secret_invalidates_its_tokens(): void {
		$old   = new TokenSigner( self::SECRET2, array(), self::NOW );
		$token = $old->sign( 'ns', array( 'u' => 1 ), 900 );

		$this->assertNull( $this->signer()->verify( 'ns', $token ) );
	}

	/* ─── Secret strength ───────────────────────────────────────────── */

	public function test_a_short_secret_is_refused(): void {
		$this->expectException( \InvalidArgumentException::class );
		new TokenSigner( 'too-short' );
	}

	public function test_a_secret_of_exactly_the_minimum_is_accepted(): void {
		$this->assertInstanceOf( TokenSigner::class, new TokenSigner( str_repeat( 'x', TokenSigner::MIN_SECRET_BYTES ) ) );
	}

	public function test_empty_retired_secrets_are_ignored(): void {
		$signer = new TokenSigner( self::SECRET, array( '', null, self::SECRET2 ), self::NOW );

		$this->assertInstanceOf( Token::class, $signer->verify( 'ns', $signer->sign( 'ns', array(), 60 ) ) );
	}

	/* ─── Payload validation ────────────────────────────────────────── */

	#[DataProvider( 'unsupported_payloads' )]
	public function test_non_scalar_claims_are_refused( array $payload ): void {
		$this->expectException( \InvalidArgumentException::class );
		$this->signer()->sign( 'ns', $payload, 60 );
	}

	/** @return array<string, array{0: array<mixed>}> */
	public static function unsupported_payloads(): array {
		return array(
			'nested array' => array( array( 'a' => array( 1, 2 ) ) ),
			'object'       => array( array( 'a' => new \stdClass() ) ),
			'null'         => array( array( 'a' => null ) ),
			'float'        => array( array( 'a' => 1.5 ) ),
			'numeric key'  => array( array( 0 => 'x' ) ),
		);
	}

	/* ─── Token accessors ───────────────────────────────────────────── */

	public function test_token_accessors(): void {
		$signer = $this->signer();
		$token  = $signer->verify( 'ns', $signer->sign( 'ns', array( 'user' => 42, 'name' => 'dave', 'ok' => true ), 60 ) );

		$this->assertNotNull( $token );
		$this->assertSame( 'ns', $token->namespace );
		$this->assertSame( 42, $token->int( 'user' ) );
		$this->assertSame( 'dave', $token->get( 'name' ) );
		$this->assertTrue( $token->get( 'ok' ) );
		$this->assertTrue( $token->has( 'user' ) );
		$this->assertFalse( $token->has( 'missing' ) );
		$this->assertNull( $token->get( 'missing' ) );
		$this->assertSame( 'fallback', $token->get( 'missing', 'fallback' ) );
		$this->assertSame( 0, $token->int( 'name' ) );
		$this->assertSame( -1, $token->int( 'missing', -1 ) );
	}

	public function test_numeric_strings_read_as_ints(): void {
		$signer = $this->signer();
		$token  = $signer->verify( 'ns', $signer->sign( 'ns', array( 'id' => '42' ), 60 ) );

		$this->assertNotNull( $token );
		$this->assertSame( 42, $token->int( 'id' ) );
	}

	/* ─── Detached signatures ───────────────────────────────────────── */

	public function test_a_detached_signature_verifies(): void {
		$signer  = $this->signer();
		$payload = array( 'customer' => 1, 'product' => 2, 'file' => 0 );
		$expiry  = self::NOW + 300;

		$this->assertTrue(
			$signer->verify_detached( 'download', $payload, $expiry, $signer->sign_detached( 'download', $payload, $expiry ) )
		);
	}

	public function test_a_detached_signature_rejects_altered_values(): void {
		$signer    = $this->signer();
		$expiry    = self::NOW + 300;
		$signature = $signer->sign_detached( 'download', array( 'customer' => 1, 'product' => 2 ), $expiry );

		$this->assertFalse( $signer->verify_detached( 'download', array( 'customer' => 1, 'product' => 3 ), $expiry, $signature ) );
	}

	public function test_a_detached_signature_rejects_an_altered_expiry(): void {
		$signer    = $this->signer();
		$payload   = array( 'customer' => 1 );
		$signature = $signer->sign_detached( 'download', $payload, self::NOW + 300 );

		$this->assertFalse( $signer->verify_detached( 'download', $payload, self::NOW + 9999, $signature ) );
	}

	public function test_a_detached_signature_expires(): void {
		$signer    = $this->signer();
		$payload   = array( 'customer' => 1 );
		$expiry    = self::NOW + 60;
		$signature = $signer->sign_detached( 'download', $payload, $expiry );

		$this->assertFalse( $this->signer( self::NOW + 61 )->verify_detached( 'download', $payload, $expiry, $signature ) );
	}

	public function test_a_detached_signature_is_namespaced(): void {
		$signer    = $this->signer();
		$payload   = array( 'customer' => 1 );
		$expiry    = self::NOW + 300;
		$signature = $signer->sign_detached( 'download', $payload, $expiry );

		$this->assertFalse( $signer->verify_detached( 'access', $payload, $expiry, $signature ) );
	}

	#[DataProvider( 'bad_detached_signatures' )]
	public function test_malformed_detached_signatures_are_rejected( string $signature ): void {
		$this->assertFalse( $this->signer()->verify_detached( 'download', array( 'a' => 1 ), self::NOW + 60, $signature ) );
	}

	/** @return array<string, array{0: string}> */
	public static function bad_detached_signatures(): array {
		return array(
			'empty'     => array( '' ),
			'short'     => array( str_repeat( 'a', 63 ) ),
			'long'      => array( str_repeat( 'a', 65 ) ),
			'uppercase' => array( str_repeat( 'A', 64 ) ),
			'non-hex'   => array( str_repeat( 'z', 64 ) ),
		);
	}

	/* ─── Per-namespace key derivation ──────────────────────────────── */

	/**
	 * Each namespace signs under its own derived subkey, so the master
	 * secret is never used directly and no two purposes share key
	 * material. This is the computed equivalent of WordPress's eight
	 * hand-managed KEY/SALT constants.
	 */
	public function test_each_namespace_signs_under_a_distinct_subkey(): void {
		$signer     = $this->signer();
		$reflection = new \ReflectionMethod( $signer, 'signature' );

		$a = $reflection->invoke( $signer, 'alpha', 'YQ', self::NOW, self::SECRET );
		$b = $reflection->invoke( $signer, 'beta', 'YQ', self::NOW, self::SECRET );

		$this->assertNotSame( $a, $b );
	}

	public function test_the_master_secret_is_never_used_as_the_signing_key(): void {
		$signer     = $this->signer();
		$reflection = new \ReflectionMethod( $signer, 'signature' );

		$this->assertNotSame(
			hash_hmac( 'sha256', 'YQ|' . self::NOW, self::SECRET ),
			$reflection->invoke( $signer, 'ns', 'YQ', self::NOW, self::SECRET )
		);
	}

	public function test_generated_secrets_are_accepted_and_unique(): void {
		$first = TokenSigner::generate_secret();

		$this->assertSame( 64, strlen( $first ) );
		$this->assertNotSame( $first, TokenSigner::generate_secret() );
		$this->assertInstanceOf( TokenSigner::class, new TokenSigner( $first ) );
	}

	/* ─── Reason messages ───────────────────────────────────────────── */

	public function test_only_expiry_gets_a_specific_public_message(): void {
		$this->assertStringContainsString( 'expired', Reason::Expired->public_message() );
		$this->assertSame( Reason::Malformed->public_message(), Reason::InvalidSignature->public_message() );
	}
}
