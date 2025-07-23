<?php
/**
 * OAuth Token Generator for Development
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

namespace OAuthPassport\Auth;

/**
 * Token Generator class
 */
class TokenGenerator {

	/**
	 * Generate development tokens for a user
	 *
	 * @param int    $user_id User ID.
	 * @param string $client_id Client ID.
	 * @param string $scope Token scope.
	 * @return array Token data.
	 */
	public static function generate_tokens( int $user_id, string $client_id, string $scope = 'read write' ): array {
		global $wpdb;
		$table = $wpdb->prefix . 'oauth_passport_tokens';

		// Generate tokens.
		$access_token  = 'oauth_passport_access_' . wp_generate_password( 32, false );
		$refresh_token = 'oauth_passport_refresh_' . wp_generate_password( 32, false );

		// Store access token (1 hour expiry).
		$wpdb->insert(
			$table,
			array(
				'token_type'  => 'access',
				'token_value' => $access_token,
				'client_id'   => $client_id,
				'user_id'     => $user_id,
				'scope'       => $scope,
				'expires_at'  => gmdate( 'Y-m-d H:i:s', time() + 3600 ),
			)
		);

		// Store refresh token (30 days expiry).
		$wpdb->insert(
			$table,
			array(
				'token_type'  => 'refresh',
				'token_value' => $refresh_token,
				'client_id'   => $client_id,
				'user_id'     => $user_id,
				'scope'       => $scope,
				'expires_at'  => gmdate( 'Y-m-d H:i:s', time() + 86400 * 30 ),
			)
		);

		return array(
			'access_token'  => $access_token,
			'refresh_token' => $refresh_token,
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
			'scope'         => $scope,
		);
	}

	/**
	 * Generate tokens via WP-CLI
	 *
	 * @param array $args Command arguments.
	 * @param array $assoc_args Associated arguments.
	 */
	public static function cli_command( $args, $assoc_args ) {
		$user_id   = isset( $args[0] ) ? intval( $args[0] ) : 1;
		$client_id = $assoc_args['client_id'] ?? 'oauth_passport_default';
		$scope     = $assoc_args['scope'] ?? 'read write';

		// Verify user exists.
		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			\WP_CLI::error( "User ID $user_id not found" );
		}

		// Generate tokens.
		$tokens = self::generate_tokens( $user_id, $client_id, $scope );

		\WP_CLI::success( 'Tokens generated successfully!' );
		\WP_CLI::line( '' );
		\WP_CLI::line( 'Access Token:  ' . $tokens['access_token'] );
		\WP_CLI::line( 'Refresh Token: ' . $tokens['refresh_token'] );
		\WP_CLI::line( 'Expires In:    ' . $tokens['expires_in'] . ' seconds' );
		\WP_CLI::line( 'Scope:         ' . $tokens['scope'] );
		\WP_CLI::line( '' );
		\WP_CLI::line( 'OAuth Configuration:' );
		\WP_CLI::line(
			json_encode(
				array(
					'auth' => array(
						'type'          => 'oauth',
						'access_token'  => $tokens['access_token'],
						'refresh_token' => $tokens['refresh_token'],
						'expires_in'    => $tokens['expires_in'],
					),
				),
				JSON_PRETTY_PRINT
			)
		);
	}
}

// Register WP-CLI command if available.
if ( defined( 'WP_CLI' ) && WP_CLI ) {
	\WP_CLI::add_command( 'oauth-passport generate-tokens', array( TokenGenerator::class, 'cli_command' ) );
} 