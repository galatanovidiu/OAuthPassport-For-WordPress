<?php
/**
 * Plugin name:       OAuth Passport
 * Description:       Transform your WordPress site into a secure OAuth 2.1 authorization server. Enable third-party applications to authenticate users and access your APIs through standards-compliant OAuth flows.
 * Version:           0.1.0
 * Requires at least: 6.4
 * Requires PHP:      8.0
 * Author:            Ovidiu Galatan
 * Author URI:        https://github.com/galatanovidiu
 * License:           MIT
 * License URI:       https://opensource.org/licenses/MIT
 * Text Domain:       oauth-passport
 * Domain Path:       /languages
 *
 * @package OAuthPassport
 */

declare(strict_types=1);

namespace OAuthPassport;

use OAuthPassport\API\AdminController;
use OAuthPassport\Auth\ClientSecretManager;
use OAuthPassport\Auth\DiscoveryServer;
use OAuthPassport\Auth\OAuth2Server;
use OAuthPassport\Runtime\Runtime;
use OAuthPassport\Auth\Schema;
use OAuthPassport\Auth\ScopeManager;
use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Repositories\ClientRepository;
use OAuthPassport\Repositories\TokenRepository;
use OAuthPassport\Services\AuthorizationService;
use OAuthPassport\Services\ClientService;
use OAuthPassport\Services\TokenService;

define( 'OAUTH_PASSPORT_VERSION', '0.1.0' );
define( 'OAUTH_PASSPORT_PATH', plugin_dir_path( __FILE__ ) );
define( 'OAUTH_PASSPORT_URL', plugin_dir_url( __FILE__ ) );


// Load Composer autoloader.
if ( file_exists( OAUTH_PASSPORT_PATH . 'vendor/autoload.php' ) ) {
	require_once OAUTH_PASSPORT_PATH . 'vendor/autoload.php';
} else {
	throw new \Exception( 'Composer autoloader not found. Please run `composer install` in the plugin directory.' );
}


function oauth_passport_runtime(): Runtime {
	global $oauth_passport_runtime;

	if ( ! isset( $oauth_passport_runtime ) || ! $oauth_passport_runtime instanceof Runtime ) {
		throw new \RuntimeException( 'OAuth Passport runtime is not initialised yet.' );
	}

	return $oauth_passport_runtime;
}


/**
 * Initialize the OAuth Passport plugin.
 */
function init_oauth_passport() {
	global $oauth_passport_runtime;

	$schema            = new Schema();
	
	// Run database migrations if needed (RFC 8707 support)
	$schema->maybe_migrate();
	
	$scope_manager     = new ScopeManager();
	$token_generator   = new SecureTokenGenerator();
	$secret_manager    = new ClientSecretManager();
	$client_repository = new ClientRepository();
	$token_repository  = new TokenRepository();

	$authorization_service = new AuthorizationService(
		$token_generator,
		$token_repository,
		$client_repository,
		$scope_manager
	);

	$token_service = new TokenService(
		$token_generator,
		$token_repository,
		$client_repository,
		$secret_manager
	);

	$client_service = new ClientService(
		$client_repository,
		$token_repository,
		$secret_manager,
		$token_generator,
		$scope_manager,
		$schema
	);

	$discovery_server = new DiscoveryServer( $scope_manager );

	new OAuth2Server(
		$schema,
		$discovery_server,
		$scope_manager,
		$authorization_service,
		$token_service,
		$secret_manager,
		$token_generator,
		$client_repository,
		$token_repository,
		$client_service
	);

	$oauth_passport_runtime = new Runtime(
		$scope_manager,
		$token_service,
		$authorization_service,
		$client_service,
		$client_repository,
		$token_repository,
		$token_generator,
		$secret_manager
	);

	$admin_controller = new AdminController( 
		$schema, 
		$scope_manager, 
		$token_generator, 
		$secret_manager,
		$client_service,
		$token_service
	);
	add_action(
		'rest_api_init',
		function () use ( $admin_controller ) {
			$admin_controller->register_routes();
		}
	);

	// phpstan-ignore-next-line - WP_CLI is loaded conditionally
	if ( defined( 'WP_CLI' ) && \WP_CLI ) {
		// phpstan-ignore-next-line
		\WP_CLI::add_command(
			'oauth-passport generate-tokens',
			function ( array $args, array $assoc_args ) use ( $token_service, $scope_manager ) {
				$user_id = isset( $args[0] ) ? (int) $args[0] : 0;
				$client_id = $assoc_args['client_id'] ?? '';
				$scope_input = $assoc_args['scope'] ?? implode( ' ', $scope_manager->getDefaultScopes() );

				if ( $user_id <= 0 || ! get_user_by( 'id', $user_id ) ) {
					\WP_CLI::error( 'Valid user ID is required.' );
				}

				if ( '' === $client_id ) {
					\WP_CLI::error( '--client_id is required.' );
				}

				$scope_string = implode( ' ', $scope_manager->validate( $scope_input ) );
				$tokens       = $token_service->issueTokens( $client_id, $user_id, $scope_string );

				\WP_CLI::success( 'Tokens generated successfully.' );
				\WP_CLI::line( '' );
				\WP_CLI::line( 'Access Token:  ' . $tokens['access_token'] );
				\WP_CLI::line( 'Refresh Token: ' . $tokens['refresh_token'] );
				\WP_CLI::line( 'Expires In:    ' . $tokens['expires_in'] . ' seconds' );
				\WP_CLI::line( 'Scope:         ' . $tokens['scope'] );
				\WP_CLI::line( '' );
				\WP_CLI::line( 'OAuth Configuration:' );
				\WP_CLI::line( wp_json_encode( array( 'auth' => array( 'type' => 'oauth', 'access_token' => $tokens['access_token'], 'refresh_token' => $tokens['refresh_token'], 'expires_in' => $tokens['expires_in'] ) ), JSON_PRETTY_PRINT ) );
			}
		);
	}
}

// Initialize the plugin on plugins_loaded to ensure all dependencies are available.
add_action( 'plugins_loaded', __NAMESPACE__ . '\\init_oauth_passport' );

/**
 * Activation hook
 */
register_activation_hook( __FILE__, __NAMESPACE__ . '\\activate_oauth_passport' );

/**
 * Handle plugin activation.
 */
function activate_oauth_passport() {
	// Create database tables.
	require_once OAUTH_PASSPORT_PATH . 'includes/Auth/Schema.php';
	$schema = new \OAuthPassport\Auth\Schema();
	$schema->create_tables();

	// Flush rewrite rules.
	flush_rewrite_rules();
}


/**
 * Deactivation hook
 */
register_deactivation_hook( __FILE__, __NAMESPACE__ . '\\deactivate_oauth_passport' );

/**
 * Handle plugin deactivation.
 */
function deactivate_oauth_passport() {
	// Clean up scheduled events.
	wp_clear_scheduled_hook( 'oauth_passport_cleanup' );

	// Flush rewrite rules.
	flush_rewrite_rules();
}
