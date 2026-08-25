<?php
/**
 * Readable token lifetimes.
 *
 * @package   ArrayPress\SignedTokens
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace ArrayPress\SignedTokens;

/**
 * Class Ttl
 *
 * `$signer->sign( 'magic-link', $claims, 900 )` is a unit bug waiting to
 * happen — 900 what? `Ttl::FIFTEEN_MINUTES` cannot be misread, and
 * `Ttl::hours( 2 )` cannot be miscalculated.
 *
 * Constants for the common cases, factories for everything else. All
 * values are plain integer seconds, so they pass straight to
 * {@see TokenSigner::sign()} with no conversion.
 *
 * **Choosing one.** A stateless token cannot be revoked, so its lifetime
 * *is* its blast radius: anyone who obtains it — from a forwarded email,
 * a shared screen, a proxy log, a browser history — can use it until it
 * expires. Pick the shortest span that still works for the user:
 *
 *   | Purpose                | Suggested            |
 *   |------------------------|----------------------|
 *   | Password reset         | {@see self::FIFTEEN_MINUTES} |
 *   | Magic sign-in          | {@see self::FIFTEEN_MINUTES} |
 *   | Email verification     | {@see self::DAY}     |
 *   | Signed download URL    | {@see self::HOUR}    |
 *   | Abandoned-cart resume  | {@see self::WEEK}    |
 *   | Unsubscribe link       | {@see self::YEAR}    |
 *
 * The long ones are defensible because the damage is bounded: an
 * unsubscribe link only unsubscribes. Nothing that grants a session
 * should outlive an hour.
 *
 * @since 1.0.0
 */
final readonly class Ttl {

	public const MINUTE           = 60;
	public const FIVE_MINUTES     = 300;
	public const TEN_MINUTES      = 600;
	public const FIFTEEN_MINUTES  = 900;
	public const THIRTY_MINUTES   = 1800;
	public const HOUR             = 3600;
	public const TWO_HOURS        = 7200;
	public const SIX_HOURS        = 21600;
	public const TWELVE_HOURS     = 43200;
	public const DAY              = 86400;
	public const THREE_DAYS       = 259200;
	public const WEEK             = 604800;
	public const THIRTY_DAYS      = 2592000;
	public const YEAR             = 31536000;

	/**
	 * N minutes in seconds.
	 *
	 * @since 1.0.0
	 *
	 * @param int $n Minutes.
	 *
	 * @return int
	 */
	public static function minutes( int $n ): int {
		return $n * self::MINUTE;
	}

	/**
	 * N hours in seconds.
	 *
	 * @since 1.0.0
	 *
	 * @param int $n Hours.
	 *
	 * @return int
	 */
	public static function hours( int $n ): int {
		return $n * self::HOUR;
	}

	/**
	 * N days in seconds.
	 *
	 * @since 1.0.0
	 *
	 * @param int $n Days.
	 *
	 * @return int
	 */
	public static function days( int $n ): int {
		return $n * self::DAY;
	}

	/**
	 * N weeks in seconds.
	 *
	 * @since 1.0.0
	 *
	 * @param int $n Weeks.
	 *
	 * @return int
	 */
	public static function weeks( int $n ): int {
		return $n * self::WEEK;
	}
}
