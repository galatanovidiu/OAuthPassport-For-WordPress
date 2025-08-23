<?php
/**
 * PKCE (Proof Key for Code Exchange) Validator
 *
 * Implements PKCE validation according to RFC 7636 for enhanced OAuth security.
 * Validates code challenges and verifiers to prevent authorization code interception.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

use Random\RandomException;

/**
 * Class PKCEValidator
 *
 * Provides PKCE (Proof Key for Code Exchange) validation functionality
 * to prevent authorization code interception attacks in OAuth flows.
 */
class PKCEValidator {
	/**
	 * Supported PKCE challenge methods
	 *
	 * Currently only supports S256 (SHA256) as required by OAuth 2.1.
	 * Plain text method is not supported for security reasons.
	 *
	 * @var array<string>
	 */
	private const SUPPORTED_METHODS = array( 'S256' );

	/**
	 * Minimum code verifier length
	 *
	 * As specified in RFC 7636, code verifiers must be at least 43 characters.
	 *
	 * @var int
	 */
	private const MIN_VERIFIER_LENGTH = 43;

	/**
	 * Maximum code verifier length
	 *
	 * As specified in RFC 7636, code verifiers must not exceed 128 characters.
	 *
	 * @var int
	 */
	private const MAX_VERIFIER_LENGTH = 128;

	/**
	 * Validate PKCE code challenge and verifier
	 *
	 * Validates that the provided code verifier generates the stored code challenge
	 * using the specified method. Uses timing-safe comparison to prevent attacks.
	 *
	 * @param string $stored_challenge The stored code challenge from authorization request
	 * @param string $verifier The code verifier provided during token exchange
	 * @param string $method The challenge method (default: S256)
	 * @return bool True if verifier matches challenge, false otherwise
	 */
	public static function validate( string $stored_challenge, string $verifier, string $method = 'S256' ): bool {
		// Validate method is supported.
		if ( ! in_array( $method, self::SUPPORTED_METHODS, true ) ) {
			return false;
		}

		// Validate verifier length.
		$verifier_length = strlen( $verifier );
		if ( $verifier_length < self::MIN_VERIFIER_LENGTH || $verifier_length > self::MAX_VERIFIER_LENGTH ) {
			return false;
		}

		// Validate verifier format (unreserved characters only).
		if ( ! preg_match( '/^[A-Za-z0-9\-._~]+$/', $verifier ) ) {
			return false;
		}

		// Calculate challenge from verifier.
		$calculated_challenge = self::generate_challenge( $verifier, $method );

		// Compare using timing-safe comparison.
		return SecurityUtils::secureCompare( $stored_challenge, $calculated_challenge );
	}

	/**
	 * Generate code challenge from verifier
	 *
	 * @param string $verifier The code verifier.
	 * @param string $method The challenge method.
	 * @return string The generated challenge.
	 */
	public static function generate_challenge( string $verifier, string $method = 'S256' ): string {
		if ( 'S256' === $method ) {
			$challenge = base64_encode( hash( 'sha256', $verifier, true ) );
			// Convert to base64url format.
			$challenge = rtrim( strtr( $challenge, '+/', '-_' ), '=' );
			return $challenge;
		}

		// This shouldn't happen as we only support S256, but return empty for safety.
		return '';
	}

	/**
	 * Generate a cryptographically secure code verifier
	 *
	 * @return string A random code verifier.
	 * @throws RandomException
	 */
	public static function generate_verifier(): string {
		// Generate 32 random bytes (256 bits).
		$random_bytes = random_bytes( 32 );

		// Convert to base64url.
		return rtrim( strtr( base64_encode( $random_bytes ), '+/', '-_' ), '=' );
	}

	/**
	 * Check if a challenge method is supported
	 *
	 * @param string $method The challenge method to check.
	 * @return bool True if supported, false otherwise.
	 */
	public static function is_method_supported( string $method ): bool {
		return in_array( $method, self::SUPPORTED_METHODS, true );
	}

	/**
	 * Get supported challenge methods
	 *
	 * @return array List of supported methods.
	 */
	public static function get_supported_methods(): array {
		return self::SUPPORTED_METHODS;
	}
} 
