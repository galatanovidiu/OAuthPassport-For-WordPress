<?php
/**
 * Test bootstrap file for OAuth Passport Plugin
 *
 * @package OAuthPassport
 */

declare(strict_types=1);

// Load Composer autoloader
require_once dirname(__DIR__) . '/vendor/autoload.php';

// Load Yoast PHPUnit polyfills for cross-version compatibility
require_once dirname(__DIR__) . '/vendor/yoast/phpunit-polyfills/phpunitpolyfills-autoload.php';

// Load test helper functions
require_once __DIR__ . '/TestHelpers.php';

// Load WordPress test environment
if (!defined('WP_TESTS_DIR')) {
    define('WP_TESTS_DIR', getenv('WP_TESTS_DIR') ?: '/tmp/wordpress-tests-lib');
}

if (!file_exists(WP_TESTS_DIR . '/includes/functions.php')) {
    echo "WordPress test library not found. Please run: composer install-wp-tests\n";
    exit(1);
}

// Load WordPress test functions
require_once WP_TESTS_DIR . '/includes/functions.php';

// Set up test database
if (!defined('DB_NAME')) {
    define('DB_NAME', getenv('WP_TEST_DB_NAME') ?: 'oauth_passport_test');
}
if (!defined('DB_USER')) {
    define('DB_USER', getenv('WP_TEST_DB_USER') ?: 'root');
}
if (!defined('DB_PASSWORD')) {
    define('DB_PASSWORD', getenv('WP_TEST_DB_PASSWORD') ?: '');
}
if (!defined('DB_HOST')) {
    define('DB_HOST', getenv('WP_TEST_DB_HOST') ?: 'localhost');
}

// Set up test environment constants
if (!defined('WP_DEBUG')) {
    define('WP_DEBUG', true);
}
if (!defined('WP_DEBUG_LOG')) {
    define('WP_DEBUG_LOG', true);
}
if (!defined('WP_DEBUG_DISPLAY')) {
    define('WP_DEBUG_DISPLAY', false);
}

// Disable external HTTP requests during tests
if (!defined('WP_HTTP_BLOCK_EXTERNAL')) {
    define('WP_HTTP_BLOCK_EXTERNAL', true);
}

// Set up test-specific filters
if (!function_exists('_oauth_passport_test_setup')) {
    function _oauth_passport_test_setup() {
        // Enable OAuth for tests
        add_filter('oauth_passport_enabled', '__return_true');
        
        // Set test-specific configuration
        add_filter('oauth_passport_access_token_lifetime', function() {
            return 3600; // 1 hour for tests
        });
        
        add_filter('oauth_passport_refresh_token_lifetime', function() {
            return 7200; // 2 hours for tests (shorter for faster cleanup testing)
        });
        
        add_filter('oauth_passport_authorization_code_lifetime', function() {
            return 600; // 10 minutes for tests
        });
        
        // Disable rate limiting for tests
        add_filter('oauth_passport_rate_limit_enabled', '__return_false');
        
        // Use faster hashing for tests (still secure but faster)
        add_filter('oauth_passport_hash_cost', function() {
            return 4; // Lower cost for faster tests
        });
    }
}

// Set up test environment
if (!function_exists('_manually_load_plugin')) {
    function _manually_load_plugin() {
        // Set up test environment
        _oauth_passport_test_setup();
        
        // Initialize the plugin
        if (function_exists('OAuthPassport\init_oauth_passport')) {
            OAuthPassport\init_oauth_passport();
        }
    }
}

// Load WordPress bootstrap
require_once WP_TESTS_DIR . '/includes/bootstrap.php';

// Load plugin
require_once dirname(__DIR__) . '/oauth-passport.php';

// Load the plugin
if (function_exists('tests_add_filter')) {
    tests_add_filter('muplugins_loaded', '_manually_load_plugin');
}

// Set up test database tables after WordPress is loaded
if (!function_exists('_oauth_passport_setup_test_tables')) {
    function _oauth_passport_setup_test_tables() {
        // Ensure database tables are created
        if (class_exists('OAuthPassport\Auth\Schema')) {
            $schema = new OAuthPassport\Auth\Schema();
            $schema->create_tables();
        }
    }
}

// Hook into WordPress init to set up tables
add_action('init', '_oauth_passport_setup_test_tables', 1);

// Set up error handling for tests
if (!function_exists('_oauth_passport_test_error_handler')) {
    function _oauth_passport_test_error_handler($errno, $errstr, $errfile, $errline) {
        // Convert errors to exceptions for better test failure reporting
        if (error_reporting() & $errno) {
            throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
        }
        return true;
    }
}

// Only set error handler if not already set
if (!ini_get('display_errors')) {
    set_error_handler('_oauth_passport_test_error_handler');
}

// Clean up function for tests
if (!function_exists('oauth_passport_cleanup_test_data')) {
    function oauth_passport_cleanup_test_data() {
        global $wpdb;
        
        // Clean up test OAuth data
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_clients WHERE client_id LIKE '%test_%'");
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_tokens WHERE client_id LIKE '%test_%'");
        
        // Clean up test options
        $wpdb->query("DELETE FROM {$wpdb->prefix}options WHERE option_name LIKE 'oauth_test_%'");
        
        // Clean up test users created during tests
        $test_users = get_users(['meta_key' => 'oauth_test_user', 'meta_value' => '1']);
        foreach ($test_users as $user) {
            wp_delete_user($user->ID);
        }
    }
}

// Register shutdown function to clean up
register_shutdown_function('oauth_passport_cleanup_test_data');
