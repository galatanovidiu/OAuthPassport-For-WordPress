<?php
/**
 * Client Secret Manager Interface
 *
 * Defines the contract for secure client secret management including
 * hashing, verification, and migration from legacy formats.
 *
 * @package OAuthPassport
 * @subpackage Contracts
 */

declare( strict_types=1 );

namespace OAuthPassport\Contracts;

/**
 * Interface ClientSecretManagerInterface
 *
 * Contract for managing client secret hashing, verification, and
 * migration using modern password hashing algorithms.
 */
interface ClientSecretManagerInterface {

	/**
	 * Hash client secret using secure algorithm
	 *
	 * Uses modern password hashing algorithms (Argon2id preferred)
	 * with configurable parameters for security and performance balance.
	 *
	 * @param string $secret Plain text client secret
	 * @param array  $options Optional hashing parameters
	 * @return string Hashed client secret
	 * @throws \InvalidArgumentException If secret is too weak
	 */
	public function hashClientSecret( string $secret, array $options = array() ): string;

	/**
	 * Verify client secret using timing-safe comparison
	 *
	 * Uses timing-safe comparison to prevent timing attacks during
	 * client secret verification. Supports legacy hash migration.
	 *
	 * @param string $secret Plain text secret to verify
	 * @param string $hash Stored hash to verify against
	 * @return bool True if secret matches hash
	 */
	public function verifyClientSecret( string $secret, string $hash ): bool;

	/**
	 * Check if hash needs rehashing
	 *
	 * Determines if a hash was created with outdated parameters
	 * or algorithms and should be rehashed for better security.
	 *
	 * @param string $hash Hash to check
	 * @param array  $options Current hashing options
	 * @return bool True if hash needs rehashing
	 */
	public function needsRehash( string $hash, array $options = array() ): bool;

	/**
	 * Generate secure client secret
	 *
	 * @return string Secure client secret
	 * @throws \Exception If random generation fails
	 */
	public function generateClientSecret(): string;
}
