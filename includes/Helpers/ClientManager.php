<?php
/**
 * Client Manager Class
 *
 * Handles OAuth client operations.
 *
 * @package OAuthPassport
 */

declare( strict_types=1 );

namespace OAuthPassport\Helpers;

/**
 * Client Manager class for handling OAuth client operations.
 */
class ClientManager {

	/**
	 * Manually register an OAuth client.
	 *
	 * @param string $client_id     The client ID.
	 * @param string $client_secret The client secret.
	 * @param string $redirect_uri  The redirect URI.
	 * @param array  $additional    Additional client data.
	 * @return bool True on success, false on failure.
	 */
	public static function register_client( string $client_id, string $client_secret, string $redirect_uri, array $additional = array() ): bool {
		$clients = get_option( 'oauth_passport_clients', array() );

		$client_data = array(
			'client_secret' => $client_secret,
			'redirect_uri'  => $redirect_uri,
		);

		// Merge additional data.
		$allowed_additional = array( 'client_name', 'scope', 'grant_types' );
		foreach ( $allowed_additional as $key ) {
			if ( isset( $additional[ $key ] ) ) {
				$client_data[ $key ] = $additional[ $key ];
			}
		}

		$clients[ $client_id ] = $client_data;

		return update_option( 'oauth_passport_clients', $clients );
	}

	/**
	 * Get OAuth client by ID.
	 *
	 * @param string $client_id The client ID.
	 * @return array|null Client data or null if not found.
	 */
	public static function get_client( string $client_id ) {
		// Check database first.
		global $wpdb;
		$table = $wpdb->prefix . 'oauth_passport_clients';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$db_client = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE client_id = %s',
				$table,
				$client_id
			),
			ARRAY_A
		);

		if ( $db_client ) {
			return $db_client;
		}

		// Fall back to option-based clients.
		$clients = get_option( 'oauth_passport_clients', array() );
		if ( isset( $clients[ $client_id ] ) ) {
			$client = $clients[ $client_id ];
			$client['client_id'] = $client_id;
			return $client;
		}

		return null;
	}
}
