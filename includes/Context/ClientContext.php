<?php
/**
 * Client Context
 *
 * Manages OAuth client operations including registration, validation,
 * and credential management with secure secret handling.
 *
 * @package OAuthPassport
 * @subpackage Context
 */

declare( strict_types=1 );

namespace OAuthPassport\Context;

use OAuthPassport\Contracts\ClientRepositoryInterface;
use OAuthPassport\Contracts\TokenGeneratorInterface;
use OAuthPassport\Contracts\ClientSecretManagerInterface;

/**
 * Class ClientContext
 *
 * Provides OAuth client management including registration, validation,
 * credential generation, and secure client secret handling.
 */
class ClientContext {

	/**
	 * Client repository
	 *
	 * @var ClientRepositoryInterface
	 */
	private ClientRepositoryInterface $client_repository;

	/**
	 * Token generator
	 *
	 * @var TokenGeneratorInterface
	 */
	private TokenGeneratorInterface $token_generator;

	/**
	 * Client secret manager
	 *
	 * @var ClientSecretManagerInterface
	 */
	private ClientSecretManagerInterface $secret_manager;

	/**
	 * Initialize client context
	 *
	 * @param ClientRepositoryInterface    $client_repository Repository for client data operations
	 * @param TokenGeneratorInterface      $token_generator Generator for secure client credentials
	 * @param ClientSecretManagerInterface $secret_manager Manager for client secret hashing and verification
	 */
	public function __construct(
		ClientRepositoryInterface $client_repository,
		TokenGeneratorInterface $token_generator,
		ClientSecretManagerInterface $secret_manager
	) {
		$this->client_repository = $client_repository;
		$this->token_generator = $token_generator;
		$this->secret_manager = $secret_manager;
	}

	/**
	 * Get client by ID
	 *
	 * Retrieves client data from the repository by client ID.
	 *
	 * @param string $client_id Client ID to lookup
	 * @return array|null Client data or null if not found
	 */
	public function getClient( string $client_id ): ?array {
		return $this->client_repository->getClient( $client_id );
	}

	/**
	 * Check if client exists
	 *
	 * Verifies whether a client with the given ID exists in the repository.
	 *
	 * @param string $client_id Client ID to check
	 * @return bool True if client exists
	 */
	public function clientExists( string $client_id ): bool {
		return null !== $this->getClient( $client_id );
	}

	/**
	 * Create new client
	 *
	 * Creates a new OAuth client with secure credentials and stores it in the repository.
	 * Generates client ID, client secret, and handles secure secret hashing.
	 *
	 * @param array $client_data Client configuration data
	 * @return array Created client with credentials (includes plain text secret)
	 * @throws \Exception If creation fails
	 */
	public function createClient( array $client_data ): array {
		// Generate secure credentials
		$client_id = $this->token_generator->generateClientId();
		$client_secret = $this->token_generator->generateClientSecret();
		$hashed_secret = $this->secret_manager->hashClientSecret( $client_secret );

		// Prepare client data
		$full_client_data = array_merge( $client_data, array(
			'client_id' => $client_id,
			'client_secret_hash' => $hashed_secret,
			'client_id_issued_at' => time(),
			'client_secret_expires_at' => 0, // Never expires
		));

		// Store client
		$success = $this->client_repository->storeClient( $full_client_data );
		if ( ! $success ) {
			throw new \RuntimeException( 'Failed to create client' );
		}

		// Return client with plain secret (only time it's exposed)
		return array_merge( $full_client_data, array(
			'client_secret' => $client_secret, // Plain text for response
		));
	}

	/**
	 * Update client
	 *
	 * @param string $client_id Client ID
	 * @param array  $update_data Data to update
	 * @return bool True on success
	 */
	public function updateClient( string $client_id, array $update_data ): bool {
		return $this->client_repository->updateClient( $client_id, $update_data );
	}

	/**
	 * Delete client
	 *
	 * @param string $client_id Client ID
	 * @return bool True on success
	 */
	public function deleteClient( string $client_id ): bool {
		return $this->client_repository->deleteClient( $client_id );
	}

	/**
	 * Get all clients
	 *
	 * @param int $limit Maximum number of clients
	 * @param int $offset Offset for pagination
	 * @return array Array of clients
	 */
	public function getAllClients( int $limit = 100, int $offset = 0 ): array {
		return $this->client_repository->getAllClients( $limit, $offset );
	}

	/**
	 * Verify client credentials
	 *
	 * @param string $client_id Client ID
	 * @param string $client_secret Client secret
	 * @return bool True if credentials are valid
	 */
	public function verifyCredentials( string $client_id, string $client_secret ): bool {
		$client = $this->getClient( $client_id );
		if ( ! $client || empty( $client['client_secret_hash'] ) ) {
			return false;
		}

		return $this->secret_manager->verifyClientSecret( $client_secret, $client['client_secret_hash'] );
	}

	/**
	 * Check if client is public (no secret)
	 *
	 * @param string $client_id Client ID
	 * @return bool True if client is public
	 */
	public function isPublicClient( string $client_id ): bool {
		$client = $this->getClient( $client_id );
		return $client && empty( $client['client_secret_hash'] );
	}

	/**
	 * Get client metadata for display
	 *
	 * @param string $client_id Client ID
	 * @return array|null Client metadata without sensitive data
	 */
	public function getClientMetadata( string $client_id ): ?array {
		$client = $this->getClient( $client_id );
		if ( ! $client ) {
			return null;
		}

		// Remove sensitive data
		unset( $client['client_secret_hash'] );
		unset( $client['registration_access_token'] );

		return $client;
	}
}
