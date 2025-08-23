<?php
/**
 * Token Generator Interface
 *
 * Defines the contract for cryptographically secure token generation
 * in OAuth 2.1 implementation with proper entropy requirements.
 *
 * @package OAuthPassport
 * @subpackage Contracts
 */

declare( strict_types=1 );

namespace OAuthPassport\Contracts;

/**
 * Interface TokenGeneratorInterface
 *
 * Contract for generating cryptographically secure OAuth tokens
 * with appropriate entropy levels for each token type.
 */
interface TokenGeneratorInterface {

	/**
	 * Generate cryptographically secure access token
	 *
	 * @return string Secure access token
	 * @throws \Exception If random generation fails
	 */
	public function generateAccessToken(): string;

	/**
	 * Generate cryptographically secure refresh token
	 *
	 * @return string Secure refresh token
	 * @throws \Exception If random generation fails
	 */
	public function generateRefreshToken(): string;

	/**
	 * Generate cryptographically secure authorization code
	 *
	 * @return string Secure authorization code
	 * @throws \Exception If random generation fails
	 */
	public function generateAuthCode(): string;

	/**
	 * Generate cryptographically secure client secret
	 *
	 * @return string Secure client secret
	 * @throws \Exception If random generation fails
	 */
	public function generateClientSecret(): string;

	/**
	 * Generate cryptographically secure client ID
	 *
	 * @return string Secure client ID
	 * @throws \Exception If random generation fails
	 */
	public function generateClientId(): string;

	/**
	 * Generate cryptographically secure registration token
	 *
	 * @return string Secure registration token
	 * @throws \Exception If random generation fails
	 */
	public function generateRegistrationToken(): string;

	/**
	 * Validate token strength and format
	 *
	 * Ensures tokens meet minimum security requirements for OAuth 2.1
	 * including proper entropy and format validation.
	 *
	 * @param string $token Token to validate
	 * @return bool True if token meets security requirements
	 */
	public function validateTokenStrength( string $token ): bool;
}
