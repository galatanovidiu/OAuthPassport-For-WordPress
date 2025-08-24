<?php
/**
 * Client Repository Implementation
 *
 * Manages OAuth client data storage and retrieval using WordPress database
 * with support for both database-stored and option-based clients.
 *
 * @package OAuthPassport
 * @subpackage Repositories
 */

declare( strict_types=1 );

namespace OAuthPassport\Repositories;

use OAuthPassport\Contracts\ClientRepositoryInterface;

/**
 * Class ClientRepository
 *
 * WordPress database implementation for OAuth client storage and retrieval
 * with JSON field handling and backward compatibility support.
 */
class ClientRepository implements ClientRepositoryInterface {

	/**
	 * OAuth clients database table name
	 *
	 * @var string
	 */
	private string $table_name;

	/**
	 * Initialize client repository
	 *
	 * Sets up the database table name for OAuth client storage.
	 */
	public function __construct() {
		global $wpdb;
		$this->table_name = $wpdb->prefix . 'oauth_passport_clients';
	}

	/**
	 * Get client by ID
	 *
	 * Retrieves client data from database or falls back to option-based storage.
	 * Handles JSON field decoding for complex data structures.
	 *
	 * @param string $client_id Client ID to retrieve
	 * @return array|null Client data or null if not found
	 */
	public function getClient( string $client_id ): ?array {
		global $wpdb;

		// First check database for dynamically registered clients
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$db_client = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE client_id = %s',
				$this->table_name,
				$client_id
			),
			ARRAY_A
		);

		if ( $db_client ) {
			// Convert JSON fields back to arrays
			if ( ! empty( $db_client['redirect_uris'] ) ) {
				$db_client['redirect_uris'] = json_decode( $db_client['redirect_uris'], true );
			}
			if ( ! empty( $db_client['grant_types'] ) ) {
				$db_client['grant_types'] = json_decode( $db_client['grant_types'], true );
			}
			if ( ! empty( $db_client['response_types'] ) ) {
				$db_client['response_types'] = json_decode( $db_client['response_types'], true );
			}
			if ( ! empty( $db_client['contacts'] ) ) {
				$db_client['contacts'] = json_decode( $db_client['contacts'], true );
			}
			
			return $db_client;
		}

		// Fall back to option-based clients for backward compatibility
		$clients = get_option( 'oauth_passport_clients', array() );
		if ( isset( $clients[ $client_id ] ) ) {
			$client = $clients[ $client_id ];
			$client['client_id'] = $client_id;
			return $client;
		}

		return null;
	}

	/**
	 * Store client
	 *
	 * Stores client data in the database with proper JSON encoding
	 * for complex fields like redirect URIs and grant types.
	 *
	 * @param array $client_data Client data to store
	 * @return bool True on success
	 */
	public function storeClient( array $client_data ): bool {
		global $wpdb;

		// Prepare data for database storage
		$db_data = $client_data;

		// Convert arrays to JSON for storage
		$json_fields = array( 'redirect_uris', 'grant_types', 'response_types', 'contacts' );
		foreach ( $json_fields as $field ) {
			if ( isset( $db_data[ $field ] ) && is_array( $db_data[ $field ] ) ) {
				$db_data[ $field ] = wp_json_encode( $db_data[ $field ] );
			}
		}

		// Add version tracking
		$db_data['secret_version'] = '2.0';

		$result = $wpdb->insert( $this->table_name, $db_data );

		return false !== $result;
	}

	/**
	 * Update client
	 *
	 * @param string $client_id Client ID
	 * @param array  $update_data Data to update
	 * @return bool True on success
	 */
	public function updateClient( string $client_id, array $update_data ): bool {
		global $wpdb;

		// Prepare data for database storage
		$db_data = $update_data;

		// Convert arrays to JSON for storage
		$json_fields = array( 'redirect_uris', 'grant_types', 'response_types', 'contacts' );
		foreach ( $json_fields as $field ) {
			if ( isset( $db_data[ $field ] ) && is_array( $db_data[ $field ] ) ) {
				$db_data[ $field ] = wp_json_encode( $db_data[ $field ] );
			}
		}

		$result = $wpdb->update(
			$this->table_name,
			$db_data,
			array( 'client_id' => $client_id )
		);

		return false !== $result;
	}

	/**
	 * Delete client
	 *
	 * @param string $client_id Client ID
	 * @return bool True on success
	 */
	public function deleteClient( string $client_id ): bool {
		global $wpdb;

		$result = $wpdb->delete(
			$this->table_name,
			array( 'client_id' => $client_id )
		);

		return false !== $result;
	}

	/**
	 * Get all clients
	 *
	 * @param int $limit Maximum number of clients to return
	 * @param int $offset Offset for pagination
	 * @return array Array of client data
	 */
	public function getAllClients( int $limit = 100, int $offset = 0 ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$clients = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT * FROM %i ORDER BY created_at DESC LIMIT %d OFFSET %d',
				$this->table_name,
				$limit,
				$offset
			),
			ARRAY_A
		);

		if ( ! $clients ) {
			return array();
		}

		// Convert JSON fields back to arrays
		foreach ( $clients as &$client ) {
			$json_fields = array( 'redirect_uris', 'grant_types', 'response_types', 'contacts' );
			foreach ( $json_fields as $field ) {
				if ( ! empty( $client[ $field ] ) ) {
					$decoded = json_decode( $client[ $field ], true );
					if ( null !== $decoded ) {
						$client[ $field ] = $decoded;
					}
				}
			}
		}

		return $clients;
	}

	/**
	 * Rehash client secret
	 *
	 * @param string $client_id Client ID
	 * @param string $new_hash New hashed secret
	 * @return bool True on success
	 */
	public function rehashClientSecret( string $client_id, string $new_hash ): bool {
		global $wpdb;

		$table_name = $this->table_name;

		$result = $wpdb->update(
			$table_name,
			array(
				'client_secret_hash' => $new_hash,
				'secret_version' => '2.0',
			),
			array( 'client_id' => $client_id ),
			array( '%s', '%s' ),
			array( '%s' )
		);

		return false !== $result;
	}
}
