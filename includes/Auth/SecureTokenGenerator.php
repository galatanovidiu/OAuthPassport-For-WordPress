<?php
/**
 * Cryptographically Secure Token Generator
 *
 * Generates OAuth tokens using cryptographically secure random number generation
 * with proper entropy levels for OAuth 2.1 compliance and security best practices.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

use OAuthPassport\Contracts\TokenGeneratorInterface;

/**
 * Class SecureTokenGenerator
 *
 * Provides cryptographically secure token generation for OAuth 2.1 implementation.
 * Uses random_bytes() with appropriate entropy levels for each token type.
 */
class SecureTokenGenerator implements TokenGeneratorInterface {

	/**
	 * Entropy requirements in bytes for different token types
	 *
	 * These values meet or exceed OAuth 2.1 security requirements
	 * and industry best practices for token generation.
	 */
	private const ACCESS_TOKEN_ENTROPY = 32;  // 256 bits
	private const REFRESH_TOKEN_ENTROPY = 32; // 256 bits
	private const AUTH_CODE_ENTROPY = 24;     // 192 bits
	private const CLIENT_SECRET_ENTROPY = 64; // 512 bits
	private const CLIENT_ID_ENTROPY = 16;     // 128 bits
	private const REGISTRATION_TOKEN_ENTROPY = 32; // 256 bits

	/**
	 * Generate cryptographically secure access token
	 *
	 * @return string Secure access token with oauth_access_ prefix
	 * @throws \Exception If random_bytes() fails
	 */
	public function generateAccessToken(): string {
		return 'oauth_access_' . bin2hex( random_bytes( self::ACCESS_TOKEN_ENTROPY ) );
	}

	/**
	 * Generate cryptographically secure refresh token
	 *
	 * @return string Secure refresh token with oauth_refresh_ prefix
	 * @throws \Exception If random_bytes() fails
	 */
	public function generateRefreshToken(): string {
		return 'oauth_refresh_' . bin2hex( random_bytes( self::REFRESH_TOKEN_ENTROPY ) );
	}

	/**
	 * Generate cryptographically secure authorization code
	 *
	 * @return string Secure authorization code with oauth_code_ prefix
	 * @throws \Exception If random_bytes() fails
	 */
	public function generateAuthCode(): string {
		return 'oauth_code_' . bin2hex( random_bytes( self::AUTH_CODE_ENTROPY ) );
	}

	/**
	 * Generate cryptographically secure client secret
	 *
	 * Uses base64 encoding for better compatibility with client implementations.
	 *
	 * @return string Secure client secret (base64 encoded)
	 * @throws \Exception If random_bytes() fails
	 */
	public function generateClientSecret(): string {
		return base64_encode( random_bytes( self::CLIENT_SECRET_ENTROPY ) );
	}

	/**
	 * Generate cryptographically secure client ID
	 *
	 * @return string Secure client ID with oauth_client_ prefix
	 * @throws \Exception If random_bytes() fails
	 */
	public function generateClientId(): string {
		return 'oauth_client_' . bin2hex( random_bytes( self::CLIENT_ID_ENTROPY ) );
	}

	/**
	 * Generate cryptographically secure registration token
	 *
	 * @return string Secure registration token with oauth_reg_ prefix
	 * @throws \Exception If random_bytes() fails
	 */
	public function generateRegistrationToken(): string {
		return 'oauth_reg_' . bin2hex( random_bytes( self::REGISTRATION_TOKEN_ENTROPY ) );
	}

	/**
	 * Generate generic secure token with custom prefix
	 *
	 * @param string $prefix Token prefix (default: 'oauth')
	 * @param int    $entropy_bytes Number of random bytes to use (default: 32)
	 * @return string Secure token with specified prefix
	 * @throws \Exception If random_bytes() fails
	 */
	public function generateToken( string $prefix = 'oauth', int $entropy_bytes = 32 ): string {
		if ( $entropy_bytes < 16 ) {
			throw new \InvalidArgumentException( 'Minimum entropy is 16 bytes (128 bits)' );
		}

		if ( $entropy_bytes > 128 ) {
			throw new \InvalidArgumentException( 'Maximum entropy is 128 bytes (1024 bits)' );
		}

		return $prefix . '_' . bin2hex( random_bytes( $entropy_bytes ) );
	}

	/**
	 * Validate token strength and format
	 *
	 * Ensures tokens meet minimum security requirements for OAuth 2.1.
	 *
	 * @param string $token Token to validate
	 * @return bool True if token meets security requirements
	 */
	public function validateTokenStrength( string $token ): bool {
		// Check minimum length (prefix + underscore + 32 hex chars = minimum 38 chars)
		if ( strlen( $token ) < 38 ) {
			return false;
		}

		// Check format: prefix_hexstring
		if ( ! preg_match( '/^[a-zA-Z0-9_]+_[a-f0-9]+$/', $token ) ) {
			return false;
		}

		// Extract hex part and validate entropy
		$parts = explode( '_', $token );
		if ( count( $parts ) < 2 ) {
			return false;
		}

		$hex_part = end( $parts );
		
		// Minimum 32 hex characters (16 bytes of entropy)
		if ( strlen( $hex_part ) < 32 ) {
			return false;
		}

		// Must be even length (valid hex)
		if ( strlen( $hex_part ) % 2 !== 0 ) {
			return false;
		}

		return true;
	}

	/**
	 * Get entropy information for a token
	 *
	 * @param string $token Token to analyze
	 * @return array Entropy information
	 */
	public function getTokenEntropy( string $token ): array {
		$parts = explode( '_', $token );
		if ( count( $parts ) < 2 ) {
			return array(
				'valid' => false,
				'entropy_bits' => 0,
				'entropy_bytes' => 0,
			);
		}

		$hex_part = end( $parts );
		$entropy_bytes = strlen( $hex_part ) / 2;
		$entropy_bits = $entropy_bytes * 8;

		return array(
			'valid' => $this->validateTokenStrength( $token ),
			'entropy_bits' => $entropy_bits,
			'entropy_bytes' => $entropy_bytes,
			'hex_length' => strlen( $hex_part ),
		);
	}

	/**
	 * Generate secure random string for general use
	 *
	 * @param int $length Length in bytes (default: 32)
	 * @return string Hex-encoded random string
	 * @throws \Exception If random_bytes() fails
	 */
	public function generateRandomString( int $length = 32 ): string {
		if ( $length < 1 ) {
			throw new \InvalidArgumentException( 'Length must be at least 1 byte' );
		}

		if ( $length > 256 ) {
			throw new \InvalidArgumentException( 'Maximum length is 256 bytes' );
		}

		return bin2hex( random_bytes( $length ) );
	}

	/**
	 * Generate URL-safe random string (base64url encoded)
	 *
	 * @param int $length Length in bytes (default: 32)
	 * @return string Base64url-encoded random string
	 * @throws \Exception If random_bytes() fails
	 */
	public function generateUrlSafeString( int $length = 32 ): string {
		if ( $length < 1 ) {
			throw new \InvalidArgumentException( 'Length must be at least 1 byte' );
		}

		if ( $length > 256 ) {
			throw new \InvalidArgumentException( 'Maximum length is 256 bytes' );
		}

		$random_bytes = random_bytes( $length );
		return rtrim( strtr( base64_encode( $random_bytes ), '+/', '-_' ), '=' );
	}

	/**
	 * Check if system has sufficient entropy
	 *
	 * @return bool True if system can generate secure random bytes
	 */
	public function hasSecureRandomSource(): bool {
		try {
			// Try to generate a small amount of random data
			random_bytes( 1 );
			return true;
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Get information about the random source being used
	 *
	 * @return array Information about random source
	 */
	public function getRandomSourceInfo(): array {
		$info = array(
			'has_secure_source' => $this->hasSecureRandomSource(),
			'php_version' => PHP_VERSION,
		);

		// Check available random sources
		if ( function_exists( 'random_bytes' ) ) {
			$info['random_bytes_available'] = true;
		}

		if ( function_exists( 'openssl_random_pseudo_bytes' ) ) {
			$info['openssl_available'] = true;
		}

		if ( is_readable( '/dev/urandom' ) ) {
			$info['dev_urandom_available'] = true;
		}

		return $info;
	}
}
