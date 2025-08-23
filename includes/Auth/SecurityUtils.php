<?php
/**
 * Security Utilities
 *
 * Provides timing-safe operations and security utilities for OAuth 2.1 implementation.
 * Includes secure string comparison, parameter validation, and cryptographic operations.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

/**
 * Class SecurityUtils
 *
 * Provides security utilities for OAuth 2.1 implementation including
 * timing-safe comparisons, secure parameter validation, and cryptographic helpers.
 */
class SecurityUtils {

	/**
	 * Timing-safe string comparison
	 *
	 * Uses hash_equals() to prevent timing attacks during string comparison.
	 * This is critical for token validation and secret verification.
	 *
	 * @param string $known_string The known/expected string
	 * @param string $user_string The user-provided string
	 * @return bool True if strings match
	 */
	public static function secureCompare( string $known_string, string $user_string ): bool {
		return hash_equals( $known_string, $user_string );
	}

	/**
	 * Timing-safe token validation
	 *
	 * Validates a provided token against a stored token using timing-safe comparison.
	 *
	 * @param string $provided_token Token provided by client
	 * @param string $stored_token Token stored in database
	 * @return bool True if tokens match
	 */
	public static function validateToken( string $provided_token, string $stored_token ): bool {
		// Ensure both tokens are non-empty
		if ( empty( $provided_token ) || empty( $stored_token ) ) {
			return false;
		}

		return self::secureCompare( $stored_token, $provided_token );
	}

	/**
	 * Generate cryptographically secure random string
	 *
	 * @param int $length Length in bytes (default: 32)
	 * @return string Hex-encoded random string
	 * @throws \Exception If random_bytes() fails
	 */
	public static function randomString( int $length = 32 ): string {
		if ( $length < 1 ) {
			throw new \InvalidArgumentException( 'Length must be at least 1 byte' );
		}

		if ( $length > 256 ) {
			throw new \InvalidArgumentException( 'Maximum length is 256 bytes' );
		}

		return bin2hex( random_bytes( $length ) );
	}

	/**
	 * Sanitize and validate OAuth parameters
	 *
	 * Removes potentially dangerous characters from OAuth parameters while
	 * preserving valid OAuth parameter characters.
	 *
	 * @param string $param Parameter value to sanitize
	 * @return string Sanitized parameter
	 */
	public static function sanitizeOAuthParam( string $param ): string {
		// Allow alphanumeric, dots, underscores, hyphens, and colons (for URIs)
		return preg_replace( '/[^a-zA-Z0-9._:-]/', '', $param );
	}

	/**
	 * Validate OAuth parameter format
	 *
	 * Checks if a parameter contains only valid OAuth characters.
	 *
	 * @param string $param Parameter to validate
	 * @return bool True if parameter is valid
	 */
	public static function isValidOAuthParam( string $param ): bool {
		// OAuth parameters should only contain unreserved characters
		return preg_match( '/^[a-zA-Z0-9._~-]+$/', $param ) === 1;
	}

	/**
	 * Generate secure nonce for CSRF protection
	 *
	 * Creates a WordPress nonce with additional entropy for OAuth operations.
	 *
	 * @param string $action Action name for nonce (default: 'oauth_passport_nonce')
	 *
	 * @return string Secure nonce
	 * @throws \Exception
	 */
	public static function generateNonce( string $action = 'oauth_passport_nonce' ): string {
		// Add additional entropy to WordPress nonce
		$entropy = self::randomString( 8 );
		return wp_create_nonce( $action . '_' . $entropy );
	}

	/**
	 * Verify nonce for CSRF protection
	 *
	 * @param string $nonce Nonce to verify
	 * @param string $action Action name for nonce (default: 'oauth_passport_nonce')
	 * @return bool True if nonce is valid
	 */
	public static function verifyNonce( string $nonce, string $action = 'oauth_passport_nonce' ): bool {
		// For enhanced nonces, we need to extract the base nonce
		if ( str_contains( $nonce, '_' ) ) {
			$parts = explode( '_', $nonce );
			if ( count( $parts ) >= 2 ) {
				// Try to verify with the enhanced action
				$enhanced_action = $action . '_' . end( $parts );
				if ( wp_verify_nonce( $nonce, $enhanced_action ) ) {
					return true;
				}
			}
		}

		// Fallback to standard nonce verification
		return wp_verify_nonce( $nonce, $action ) !== false;
	}

	/**
	 * Validate redirect URI security
	 *
	 * Performs security checks on redirect URIs to prevent open redirect attacks.
	 *
	 * @param string $redirect_uri URI to validate
	 * @param array  $allowed_hosts Optional array of allowed hosts
	 * @return bool True if URI is safe
	 */
	public static function isSecureRedirectUri( string $redirect_uri, array $allowed_hosts = array() ): bool {
		// Parse the URI
		$parsed = wp_parse_url( $redirect_uri );
		if ( false === $parsed || empty( $parsed['scheme'] ) || empty( $parsed['host'] ) ) {
			return false;
		}

		// Only allow HTTPS in production (allow HTTP for localhost in development)
		$scheme = strtolower( $parsed['scheme'] );
		if ( 'https' !== $scheme ) {
			// Allow HTTP only for localhost/development
			if ( 'http' === $scheme && self::isLocalhostHost( $parsed['host'] ) ) {
				// OK for development
			} else {
				return false;
			}
		}

		// Check against allowed hosts if provided
		if ( ! empty( $allowed_hosts ) ) {
			$host = strtolower( $parsed['host'] );
			$allowed_hosts = array_map( 'strtolower', $allowed_hosts );
			
			if ( ! in_array( $host, $allowed_hosts, true ) ) {
				return false;
			}
		}

		// Additional security checks
		if ( ! self::isValidHost( $parsed['host'] ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Check if host is localhost/development
	 *
	 * @param string $host Host to check
	 * @return bool True if host is localhost
	 */
	public static function isLocalhostHost( string $host ): bool {
		$localhost_patterns = array(
			'localhost',
			'127.0.0.1',
			'::1',
			'0.0.0.0',
		);

		$host = strtolower( $host );

		foreach ( $localhost_patterns as $pattern ) {
			if ( $host === $pattern || str_starts_with( $host, $pattern . ':' ) ) {
				return true;
			}
		}

		// Check for *.local domains
		if ( str_ends_with( $host, '.local' ) ) {
			return true;
		}

		// Check for private IP ranges
		if ( filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE ) === false ) {
			return true;
		}

		return false;
	}

	/**
	 * Validate host format
	 *
	 * @param string $host Host to validate
	 * @return bool True if host format is valid
	 */
	private static function isValidHost( string $host ): bool {
		// Check for valid hostname or IP address
		if ( filter_var( $host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME ) ) {
			return true;
		}

		if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Generate secure state parameter
	 *
	 * Creates a cryptographically secure state parameter for OAuth flows.
	 *
	 * @return string Secure state parameter
	 * @throws \Exception If random generation fails
	 */
	public static function generateState(): string {
		return self::randomString( 32 );
	}

	/**
	 * Validate state parameter format
	 *
	 * @param string $state State parameter to validate
	 * @return bool True if state format is valid
	 */
	public static function isValidState( string $state ): bool {
		// State should be a hex string of reasonable length
		return preg_match( '/^[a-f0-9]{32,128}$/', $state ) === 1;
	}

	/**
	 * Hash sensitive data for logging
	 *
	 * Creates a hash of sensitive data that can be safely logged for debugging
	 * without exposing the actual sensitive information.
	 *
	 * @param string $sensitive_data Data to hash
	 * @return string SHA-256 hash (first 16 characters)
	 */
	public static function hashForLogging( string $sensitive_data ): string {
		return substr( hash( 'sha256', $sensitive_data ), 0, 16 );
	}

	/**
	 * Constant-time length comparison
	 *
	 * Compares string lengths in constant time to prevent timing attacks
	 * based on length differences.
	 *
	 * @param string $str1 First string
	 * @param string $str2 Second string
	 * @return bool True if lengths match
	 */
	public static function constantTimeLengthEquals( string $str1, string $str2 ): bool {
		$len1 = strlen( $str1 );
		$len2 = strlen( $str2 );
		
		// Use bitwise XOR to compare lengths in constant time
		return 0 === ( $len1 ^ $len2 );
	}

	/**
	 * Secure array comparison
	 *
	 * Compares arrays in a timing-safe manner.
	 *
	 * @param array $array1 First array
	 * @param array $array2 Second array
	 * @return bool True if arrays are identical
	 */
	public static function secureArrayCompare( array $array1, array $array2 ): bool {
		// First check if they have the same number of elements
		if ( count( $array1 ) !== count( $array2 ) ) {
			return false;
		}

		// Sort both arrays to ensure consistent comparison
		ksort( $array1 );
		ksort( $array2 );

		// Convert to JSON for comparison (ensures consistent serialization)
		$json1 = wp_json_encode( $array1 );
		$json2 = wp_json_encode( $array2 );

		if ( false === $json1 || false === $json2 ) {
			return false;
		}

		return self::secureCompare( $json1, $json2 );
	}

	/**
	 * Rate limiting helper
	 *
	 * Simple rate limiting based on IP address and action.
	 *
	 * @param string $action Action being rate limited
	 * @param int    $max_attempts Maximum attempts allowed
	 * @param int    $time_window Time window in seconds
	 * @return bool True if action is allowed, false if rate limited
	 */
	public static function isRateLimited( string $action, int $max_attempts = 10, int $time_window = 3600 ): bool {
		$ip = self::getClientIp();
		$key = 'oauth_rate_limit_' . md5( $action . '_' . $ip );
		
		$attempts = get_transient( $key );
		if ( false === $attempts ) {
			$attempts = 0;
		}

		if ( $attempts >= $max_attempts ) {
			return true; // Rate limited
		}

		// Increment counter
		set_transient( $key, $attempts + 1, $time_window );
		
		return false; // Not rate limited
	}

	/**
	 * Get client IP address
	 *
	 * Attempts to get the real client IP address, considering proxies.
	 *
	 * @return string Client IP address
	 */
	public static function getClientIp(): string {
		$headers = array(
			'HTTP_CF_CONNECTING_IP',     // Cloudflare
			'HTTP_CLIENT_IP',            // Proxy
			'HTTP_X_FORWARDED_FOR',      // Load balancer/proxy
			'HTTP_X_FORWARDED',          // Proxy
			'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
			'HTTP_FORWARDED_FOR',        // Proxy
			'HTTP_FORWARDED',            // Proxy
			'REMOTE_ADDR',               // Standard
		);

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				
				// Handle comma-separated IPs (X-Forwarded-For can contain multiple IPs)
				if ( str_contains( $ip, ',' ) ) {
					$ip = trim( explode( ',', $ip )[0] );
				}
				
				// Validate IP address
				if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
					return $ip;
				}
			}
		}

		// Fallback to REMOTE_ADDR even if it's private/reserved
		return sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1' ) );
	}

	/**
	 * Clear rate limiting for an action
	 *
	 * @param string $action Action to clear rate limiting for
	 * @return bool True if cleared successfully
	 */
	public static function clearRateLimit( string $action ): bool {
		$ip = self::getClientIp();
		$key = 'oauth_rate_limit_' . md5( $action . '_' . $ip );
		
		return delete_transient( $key );
	}
}
