<?php
/**
 * Client Repository Interface
 *
 * Defines the contract for client storage and retrieval operations.
 *
 * @package OAuthPassport
 * @subpackage Contracts
 */

declare( strict_types=1 );

namespace OAuthPassport\Contracts;

/**
 * Interface ClientRepositoryInterface
 *
 * Contract for client storage and retrieval operations.
 */
interface ClientRepositoryInterface {

	/**
	 * Get client by ID
	 *
	 * @param string $client_id Client ID
	 * @return array|null Client data or null if not found
	 */
	public function getClient( string $client_id ): ?array;

	/**
	 * Store client
	 *
	 * @param array $client_data Client data
	 * @return bool True on success
	 */
	public function storeClient( array $client_data ): bool;

	/**
	 * Update client
	 *
	 * @param string $client_id Client ID
	 * @param array  $update_data Data to update
	 * @return bool True on success
	 */
	public function updateClient( string $client_id, array $update_data ): bool;

	/**
	 * Delete client
	 *
	 * @param string $client_id Client ID
	 * @return bool True on success
	 */
	public function deleteClient( string $client_id ): bool;

	/**
	 * Get all clients
	 *
	 * @param int $limit Maximum number of clients to return
	 * @param int $offset Offset for pagination
	 * @return array Array of client data
	 */
	public function getAllClients( int $limit = 100, int $offset = 0 ): array;

	/**
	 * Rehash client secret
	 *
	 * @param string $client_id Client ID
	 * @param string $new_hash New hashed secret
	 * @return bool True on success
	 */
	public function rehashClientSecret( string $client_id, string $new_hash ): bool;
}
