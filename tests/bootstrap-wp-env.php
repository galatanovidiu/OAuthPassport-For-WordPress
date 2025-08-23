<?php
/**
 * Test bootstrap file for OAuth Passport Plugin with wp-env
 *
 * @package OAuthPassport
 */

declare(strict_types=1);

// Load Composer autoloader
require_once dirname(__DIR__) . '/vendor/autoload.php';

// Define WordPress constants for wp-env
if (!defined('ABSPATH')) {
    define('ABSPATH', '/var/www/html/');
}

// Load WordPress
require_once ABSPATH . 'wp-config.php';
require_once ABSPATH . 'wp-settings.php';

// Load plugin
require_once dirname(__DIR__) . '/oauth-passport.php';

// Initialize the plugin
if (function_exists('OAuthPassport\init_oauth_passport')) {
    OAuthPassport\init_oauth_passport();
}

// Mock WordPress test functions if needed
if (!class_exists('WP_UnitTestCase')) {
    class WP_UnitTestCase extends PHPUnit\Framework\TestCase {
        public function setUp(): void {
            parent::setUp();
        }
        
        public function tearDown(): void {
            parent::tearDown();
        }
    }
}
