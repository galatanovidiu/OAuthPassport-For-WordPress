<?php
/**
 * OAuth Passport Helper Functions
 *
 * Global functions for integrating with OAuth Passport.
 *
 * @package OAuthPassport
 */

declare( strict_types=1 );

/**
 * Get the current OAuth token if the request is authenticated via OAuth.
 *
 * @return object|null Token object with user_id, client_id, scope, etc. or null if not OAuth authenticated.
 */
function oauth_passport_get_current_token() {
	// Check if we have an OAuth token in the current request.
	$auth_header = '';
	if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
		$auth_header = sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) );
	} elseif ( isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
		$auth_header = sanitize_text_field( wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) );
	}

	if ( empty( $auth_header ) || ! preg_match( '/Bearer\s+(.+)/i', $auth_header, $matches ) ) {
		return null;
	}

	$token = $matches[1];

	// Skip if it looks like a JWT (has dots).
	if ( str_contains( $token, '.' ) ) {
		return null;
	}

	// Look up the token in the database.
	global $wpdb;
	$table = $wpdb->prefix . 'oauth_passport_tokens';

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
	$token_data = $wpdb->get_row(
		$wpdb->prepare(
			"SELECT * FROM %i 
			WHERE token_type = 'access' 
			AND token_value = %s 
			AND expires_at > %s",
			$table,
			$token,
			gmdate( 'Y-m-d H:i:s' )
		)
	);

	return $token_data;
}

/**
 * Check if the current user has a specific OAuth scope.
 *
 * @param string $scope The scope to check for.
 * @return bool True if the user has the scope, false otherwise.
 */
function oauth_passport_user_has_scope( string $scope ): bool {
	$token = oauth_passport_get_current_token();
	if ( ! $token ) {
		return false;
	}

	$token_scopes = explode( ' ', $token->scope );
	return in_array( $scope, $token_scopes, true );
}

/**
 * Get all available OAuth scopes.
 *
 * @return array Array of scope => description pairs.
 */
function oauth_passport_get_available_scopes(): array {
	$default_scopes = array(
		'read'       => __( 'Read access to resources', 'oauth-passport' ),
		'write'      => __( 'Write access to resources', 'oauth-passport' ),
		'admin'      => __( 'Administrative access', 'oauth-passport' ),
		'user:read'  => __( 'Read user information', 'oauth-passport' ),
		'user:write' => __( 'Modify user information', 'oauth-passport' ),
	);

	/**
	 * Filter the available OAuth scopes.
	 *
	 * @param array $scopes Array of scope => description pairs.
	 */
	return apply_filters( 'oauth_passport_scopes', $default_scopes );
}

/**
 * Check if OAuth Passport is enabled.
 *
 * @return bool True if OAuth is enabled, false otherwise.
 */
function oauth_passport_is_enabled(): bool {
	/**
	 * Filter whether OAuth Passport is enabled.
	 *
	 * @param bool $enabled Whether OAuth is enabled. Default true.
	 */
	return apply_filters( 'oauth_passport_enabled', true );
}

/**
 * Get the OAuth authorization URL.
 *
 * @param array $params Query parameters for the authorization request.
 * @return string The authorization URL.
 */
function oauth_passport_get_authorize_url( array $params = array() ): string {
	$defaults = array(
		'response_type' => 'code',
	);
	$params = wp_parse_args( $params, $defaults );

	return add_query_arg( $params, rest_url( 'oauth-passport/v1/authorize' ) );
}

/**
 * Get the OAuth token URL.
 *
 * @return string The token endpoint URL.
 */
function oauth_passport_get_token_url(): string {
	return rest_url( 'oauth-passport/v1/token' );
}

/**
 * Get the OAuth client registration URL.
 *
 * @return string The registration endpoint URL.
 */
function oauth_passport_get_registration_url(): string {
	return rest_url( 'oauth-passport/v1/register' );
}

/**
 * Manually register an OAuth client.
 *
 * @param string $client_id     The client ID.
 * @param string $client_secret The client secret.
 * @param string $redirect_uri  The redirect URI.
 * @param array  $additional    Additional client data.
 * @return bool True on success, false on failure.
 */
function oauth_passport_register_client( string $client_id, string $client_secret, string $redirect_uri, array $additional = array() ): bool {
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
 * Revoke an OAuth token.
 *
 * @param string $token The token to revoke.
 * @return bool True on success, false on failure.
 */
function oauth_passport_revoke_token( string $token ): bool {
	global $wpdb;
	$table = $wpdb->prefix . 'oauth_passport_tokens';

	$result = $wpdb->delete(
		$table,
		array( 'token_value' => $token )
	);

	return false !== $result;
}

/**
 * Get OAuth client by ID.
 *
 * @param string $client_id The client ID.
 * @return array|null Client data or null if not found.
 */
function oauth_passport_get_client( string $client_id ) {
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