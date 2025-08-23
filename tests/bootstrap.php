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
require_once WP_TESTS_DIR . '/includes/bootstrap.php';

// Load plugin
require_once dirname(__DIR__) . '/oauth-passport.php';

// Set up test environment
if (!function_exists('_manually_load_plugin')) {
    function _manually_load_plugin() {
        // Initialize the plugin
        OAuthPassport\init_oauth_passport();
    }
}

// Load the plugin
if (function_exists('tests_add_filter')) {
    tests_add_filter('muplugins_loaded', '_manually_load_plugin');
}
