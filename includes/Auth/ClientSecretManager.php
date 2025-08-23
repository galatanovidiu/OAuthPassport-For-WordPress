<?php
/**
 * Client Secret Manager
 *
 * Manages OAuth client secret hashing and verification using modern password
 * hashing algorithms including Argon2id for enhanced security.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

use OAuthPassport\Contracts\ClientSecretManagerInterface;

/**
 * Class ClientSecretManager
 *
 * Handles OAuth client secret hashing and verification using modern algorithms.
 * Supports Argon2id, Argon2i, and bcrypt with automatic migration from legacy formats.
 */
class ClientSecretManager implements ClientSecretManagerInterface {

	/**
	 * Default Argon2id hashing parameters
	 *
	 * These values provide strong security while maintaining reasonable
	 * performance for typical WordPress hosting environments.
	 */
	private const DEFAULT_MEMORY_COST = 65536;  // 64MB
	private const DEFAULT_TIME_COST = 4;        // 4 iterations
	private const DEFAULT_THREADS = 3;          // 3 threads

	/**
	 * Minimum security parameters
	 *
	 * These represent the absolute minimum values required
	 * to maintain acceptable security standards.
	 */
	private const MIN_MEMORY_COST = 32768;      // 32MB
	private const MIN_TIME_COST = 2;            // 2 iterations
	private const MIN_THREADS = 1;              // 1 thread

	/**
	 * Token generator instance
	 *
	 * @var SecureTokenGenerator
	 */
	private SecureTokenGenerator $token_generator;

	/**
	 * Initialize client secret manager
	 *
	 * Sets up the secure token generator for client secret generation.
	 */
	public function __construct() {
		$this->token_generator = new SecureTokenGenerator();
	}

	/**
	 * Hash client secret using Argon2id
	 *
	 * Uses Argon2id algorithm which is resistant to both side-channel attacks
	 * and GPU-based attacks. Parameters are tuned for WordPress hosting environments.
	 *
	 * @param string $secret Plain text client secret
	 * @param array  $options Optional hashing parameters
	 * @return string Hashed client secret
	 * @throws \InvalidArgumentException If secret is too weak
	 */
	public function hashClientSecret( string $secret, array $options = array() ): string {
		// Validate secret strength
		if ( strlen( $secret ) < 32 ) {
			throw new \InvalidArgumentException( 'Client secret must be at least 32 characters long' );
		}

		// Merge with default options
		$hash_options = array_merge(
			array(
				'memory_cost' => self::DEFAULT_MEMORY_COST,
				'time_cost'   => self::DEFAULT_TIME_COST,
				'threads'     => self::DEFAULT_THREADS,
			),
			$options
		);

		// Validate parameters
		$this->validateHashingParameters( $hash_options );

		// Use Argon2id if available, fallback to Argon2i
		$algorithm = defined( 'PASSWORD_ARGON2ID' ) ? PASSWORD_ARGON2ID : PASSWORD_ARGON2I;

		$hash = password_hash( $secret, $algorithm, $hash_options );

		if ( false === $hash ) {
			throw new \RuntimeException( 'Failed to hash client secret' );
		}

		return $hash;
	}

	/**
	 * Verify client secret using timing-safe comparison
	 *
	 * Uses password_verify() which internally uses timing-safe comparison
	 * to prevent timing attacks during verification.
	 *
	 * @param string $secret Plain text secret to verify
	 * @param string $hash Stored hash to verify against
	 * @return bool True if secret matches hash
	 */
	public function verifyClientSecret( string $secret, string $hash ): bool {
		// Handle empty or invalid inputs
		if ( empty( $secret ) || empty( $hash ) ) {
			return false;
		}

		// Check if this is a legacy hash format
		if ( $this->isLegacyHash( $hash ) ) {
			return $this->verifyLegacySecret( $secret, $hash );
		}

		// Use password_verify for Argon2 hashes
		return password_verify( $secret, $hash );
	}

	/**
	 * Check if hash needs rehashing
	 *
	 * Determines if a hash was created with outdated parameters and should be rehashed.
	 *
	 * @param string $hash Hash to check
	 * @param array  $options Current hashing options
	 * @return bool True if hash needs rehashing
	 */
	public function needsRehash( string $hash, array $options = array() ): bool {
		// Legacy hashes always need rehashing
		if ( $this->isLegacyHash( $hash ) ) {
			return true;
		}

		// Merge with default options
		$hash_options = array_merge(
			array(
				'memory_cost' => self::DEFAULT_MEMORY_COST,
				'time_cost'   => self::DEFAULT_TIME_COST,
				'threads'     => self::DEFAULT_THREADS,
			),
			$options
		);

		$algorithm = defined( 'PASSWORD_ARGON2ID' ) ? PASSWORD_ARGON2ID : PASSWORD_ARGON2I;

		return password_needs_rehash( $hash, $algorithm, $hash_options );
	}

	/**
	 * Generate secure client secret
	 *
	 * Creates a cryptographically secure client secret using the token generator.
	 *
	 * @return string Secure client secret
	 * @throws \Exception If random generation fails
	 */
	public function generateClientSecret(): string {
		return $this->token_generator->generateClientSecret();
	}

	/**
	 * Migrate legacy hash to new format
	 *
	 * Handles migration from old wp_hash() format to new Argon2id format.
	 * This should be called during authentication when a legacy hash is detected.
	 *
	 * @param string $secret Plain text secret
	 * @param string $legacy_hash Old hash format
	 * @return string|null New hash if migration successful, null if verification failed
	 */
	public function migrateLegacyHash( string $secret, string $legacy_hash ): ?string {
		// Verify the secret against the legacy hash first
		if ( ! $this->verifyLegacySecret( $secret, $legacy_hash ) ) {
			return null;
		}

		// Generate new hash
		try {
			return $this->hashClientSecret( $secret );
		} catch ( \Exception $e ) {
			// Log error but don't expose details
			error_log( 'OAuth Passport: Failed to migrate legacy hash: ' . $e->getMessage() );
			return null;
		}
	}

	/**
	 * Get hashing algorithm information
	 *
	 * @return array Information about available algorithms
	 */
	public function getAlgorithmInfo(): array {
		$info = array(
			'php_version' => PHP_VERSION,
			'available_algorithms' => array(),
			'recommended_algorithm' => null,
		);

		// Check available algorithms
		if ( defined( 'PASSWORD_ARGON2ID' ) ) {
			$info['available_algorithms'][] = 'argon2id';
			$info['recommended_algorithm'] = 'argon2id';
		}

		if ( defined( 'PASSWORD_ARGON2I' ) ) {
			$info['available_algorithms'][] = 'argon2i';
			if ( ! $info['recommended_algorithm'] ) {
				$info['recommended_algorithm'] = 'argon2i';
			}
		}

		$info['available_algorithms'][] = 'bcrypt';
		if ( ! $info['recommended_algorithm'] ) {
			$info['recommended_algorithm'] = 'bcrypt';
		}

		return $info;
	}

	/**
	 * Validate hashing parameters
	 *
	 * @param array $options Hashing options to validate
	 * @throws \InvalidArgumentException If parameters are invalid
	 */
	private function validateHashingParameters( array $options ): void {
		if ( isset( $options['memory_cost'] ) && $options['memory_cost'] < self::MIN_MEMORY_COST ) {
			throw new \InvalidArgumentException(
				sprintf( 'Memory cost must be at least %d KB', self::MIN_MEMORY_COST )
			);
		}

		if ( isset( $options['time_cost'] ) && $options['time_cost'] < self::MIN_TIME_COST ) {
			throw new \InvalidArgumentException(
				sprintf( 'Time cost must be at least %d', self::MIN_TIME_COST )
			);
		}

		if ( isset( $options['threads'] ) && $options['threads'] < self::MIN_THREADS ) {
			throw new \InvalidArgumentException(
				sprintf( 'Thread count must be at least %d', self::MIN_THREADS )
			);
		}
	}

	/**
	 * Check if hash is in legacy format
	 *
	 * Detects old wp_hash() or other legacy hash formats that need migration.
	 *
	 * @param string $hash Hash to check
	 * @return bool True if hash is in legacy format
	 */
	private function isLegacyHash( string $hash ): bool {
		// Argon2 hashes start with $argon2
		if ( str_starts_with( $hash, '$argon2' ) ) {
			return false;
		}

		// bcrypt hashes start with $2y$, $2a$, or $2x$
		if ( preg_match( '/^\$2[axy]\$/', $hash ) ) {
			return false;
		}

		// Everything else is considered legacy
		return true;
	}

	/**
	 * Verify secret against legacy hash
	 *
	 * Handles verification for old hash formats including wp_hash() and plain text.
	 *
	 * @param string $secret Plain text secret
	 * @param string $legacy_hash Legacy hash
	 * @return bool True if secret matches legacy hash
	 */
	private function verifyLegacySecret( string $secret, string $legacy_hash ): bool {
		// Check if it's a WordPress password hash (phpass or bcrypt)
		if ( str_starts_with( $legacy_hash, '$P$' ) || str_starts_with( $legacy_hash, '$wp$' ) ) {
			return wp_check_password( $secret, $legacy_hash );
		}

		// Check if it's a plain wp_hash() result (32 character hex string)
		if ( preg_match( '/^[a-f0-9]{32}$/', $legacy_hash ) ) {
			// Use timing-safe comparison for wp_hash verification
			return hash_equals( $legacy_hash, wp_hash( $secret ) );
		}

		// For any other legacy format, use timing-safe comparison
		return hash_equals( $legacy_hash, $secret );
	}

	/**
	 * Get hash information
	 *
	 * Analyzes a hash and returns information about its format and parameters.
	 *
	 * @param string $hash Hash to analyze
	 * @return array Hash information
	 */
	public function getHashInfo( string $hash ): array {
		$info = array(
			'algorithm' => 'unknown',
			'is_legacy' => $this->isLegacyHash( $hash ),
			'needs_rehash' => false,
			'parameters' => array(),
		);

		if ( $info['is_legacy'] ) {
			$info['needs_rehash'] = true;
			
			if ( str_starts_with( $hash, '$P$' ) ) {
				$info['algorithm'] = 'phpass';
			} elseif ( str_starts_with( $hash, '$wp$' ) ) {
				$info['algorithm'] = 'wordpress_bcrypt';
			} elseif ( preg_match( '/^[a-f0-9]{32}$/', $hash ) ) {
				$info['algorithm'] = 'wp_hash';
			} else {
				$info['algorithm'] = 'plain_text';
			}
		} else {
			// Parse modern hash formats
			if ( str_starts_with( $hash, '$argon2id$' ) ) {
				$info['algorithm'] = 'argon2id';
				$info['parameters'] = $this->parseArgon2Hash( $hash );
			} elseif ( str_starts_with( $hash, '$argon2i$' ) ) {
				$info['algorithm'] = 'argon2i';
				$info['parameters'] = $this->parseArgon2Hash( $hash );
			} elseif ( preg_match( '/^\$2[axy]\$/', $hash ) ) {
				$info['algorithm'] = 'bcrypt';
				$info['parameters'] = $this->parseBcryptHash( $hash );
			}

			$info['needs_rehash'] = $this->needsRehash( $hash );
		}

		return $info;
	}

	/**
	 * Parse Argon2 hash parameters
	 *
	 * @param string $hash Argon2 hash
	 * @return array Parsed parameters
	 */
	private function parseArgon2Hash( string $hash ): array {
		$parts = explode( '$', $hash );
		$parameters = array();

		if ( count( $parts ) >= 4 ) {
			$params_string = $parts[3];
			$param_pairs = explode( ',', $params_string );

			foreach ( $param_pairs as $pair ) {
				if ( str_contains( $pair, '=' ) ) {
					list( $key, $value ) = explode( '=', $pair, 2 );
					$parameters[ $key ] = $value;
				}
			}
		}

		return $parameters;
	}

	/**
	 * Parse bcrypt hash parameters
	 *
	 * @param string $hash bcrypt hash
	 * @return array Parsed parameters
	 */
	private function parseBcryptHash( string $hash ): array {
		$parts = explode( '$', $hash );
		$parameters = array();

		if ( count( $parts ) >= 3 ) {
			$parameters['cost'] = intval( $parts[2] );
		}

		return $parameters;
	}
}
