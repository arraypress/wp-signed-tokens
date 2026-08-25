<?php
/**
 * Why a token failed verification.
 *
 * @package   ArrayPress\SignedTokens
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.0.0
 */

declare( strict_types=1 );

namespace ArrayPress\SignedTokens;

/**
 * Enum Reason
 *
 * Returned by {@see TokenSigner::inspect()} so the caller can say
 * "this link has expired, request a new one" instead of a flat
 * "invalid link" for every failure.
 *
 * Note the ordering guarantee: a token is only reported as `Expired`
 * **after** its signature has been verified. A forged token is always
 * `InvalidSignature`, never `Expired`, so nothing here tells an attacker
 * whether they got the structure right.
 *
 * @since 1.0.0
 */
enum Reason: string {

	/**
	 * Not shaped like a token at all — wrong segment count, undecodable
	 * base64, or a payload that isn't a JSON object.
	 */
	case Malformed = 'malformed';

	/**
	 * Signature did not match under any known secret. Either tampered
	 * with, or signed under a secret that has since been retired.
	 */
	case InvalidSignature = 'invalid_signature';

	/**
	 * Genuinely signed by us, but past its expiry.
	 */
	case Expired = 'expired';

	/**
	 * Message safe to show an end user.
	 *
	 * Deliberately vague for everything except expiry, which is the one
	 * case where a specific message helps rather than leaks.
	 *
	 * @since 1.0.0
	 *
	 * @return string
	 */
	public function public_message(): string {
		return match ( $this ) {
			self::Expired => 'This link has expired. Please request a new one.',
			default       => 'This link is not valid.',
		};
	}
}
