<?php
/**
 * Cryptographically Secure Token Generator
 *
 * Generates the small set of token shapes required by the plugin using
 * PHP's random_bytes() API.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

/**
 * Class SecureTokenGenerator
 */
class SecureTokenGenerator {
	private const ACCESS_TOKEN_ENTROPY       = 32; // 256 bits.
	private const REFRESH_TOKEN_ENTROPY      = 32; // 256 bits.
	private const AUTH_CODE_ENTROPY          = 24; // 192 bits.
	private const CLIENT_SECRET_ENTROPY      = 64; // 512 bits.
	private const CLIENT_ID_ENTROPY          = 16; // 128 bits.
	private const REGISTRATION_TOKEN_ENTROPY = 32; // 256 bits.

	/**
	 * Generate an opaque access token value.
	 */
	public function generateAccessToken(): string {
		return $this->hexToken( 'oauth_access_', self::ACCESS_TOKEN_ENTROPY );
	}

	/**
	 * Generate an opaque refresh token value.
	 */
	public function generateRefreshToken(): string {
		return $this->hexToken( 'oauth_refresh_', self::REFRESH_TOKEN_ENTROPY );
	}

	/**
	 * Generate an authorization code.
	 */
	public function generateAuthCode(): string {
		return $this->hexToken( 'oauth_code_', self::AUTH_CODE_ENTROPY );
	}

	/**
	 * Generate a client secret (base64 encoded to keep it compact).
	 */
	public function generateClientSecret(): string {
		return base64_encode( random_bytes( self::CLIENT_SECRET_ENTROPY ) );
	}

	/**
	 * Generate a public client identifier.
	 */
	public function generateClientId(): string {
		return $this->hexToken( 'oauth_client_', self::CLIENT_ID_ENTROPY );
	}

	/**
	 * Generate a token used to manage dynamic client registrations.
	 */
	public function generateRegistrationToken(): string {
		return $this->hexToken( 'oauth_reg_', self::REGISTRATION_TOKEN_ENTROPY );
	}

	private function hexToken( string $prefix, int $entropy_bytes ): string {
		return $prefix . bin2hex( random_bytes( $entropy_bytes ) );
	}
}
