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

use OAuthPassport\Auth\OAuth2Server;
use OAuthPassport\API\AdminController;

define( 'OAUTH_PASSPORT_VERSION', '0.1.0' );
define( 'OAUTH_PASSPORT_PATH', plugin_dir_path( __FILE__ ) );
define( 'OAUTH_PASSPORT_URL', plugin_dir_url( __FILE__ ) );


// Load Composer autoloader.
if ( file_exists( OAUTH_PASSPORT_PATH . 'vendor/autoload.php' ) ) {
	require_once OAUTH_PASSPORT_PATH . 'vendor/autoload.php';
} else {
	throw new \Exception( 'Composer autoloader not found. Please run `composer install` in the plugin directory.' );
}



/**
 * Initialize the OAuth Passport plugin.
 */
function init_oauth_passport() {
	// Initialize OAuth 2.1 server.
	new OAuth2Server();

	// Register admin API endpoints.
	add_action(
		'rest_api_init',
		function () {
			$admin_controller = new AdminController();
			$admin_controller->register_routes();
		}
	);
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
