<?php
/**
 * Test bootstrap file for OAuth Passport Plugin with wp-env
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

// Define WordPress constants for wp-env
if (!defined('ABSPATH')) {
    define('ABSPATH', '/var/www/html/');
}

// Set up WordPress test environment
if (!defined('WP_TESTS_DIR')) {
    define('WP_TESTS_DIR', '/var/www/html/wp-content/plugins/wordpress-develop/tests/phpunit');
}

// Try to find WordPress test framework
$wp_test_locations = [
    '/var/www/html/wp-content/plugins/wordpress-develop/tests/phpunit',
    '/tmp/wordpress-tests-lib',
    '/var/www/html/wp-tests-lib'
];

$wp_tests_found = false;
foreach ($wp_test_locations as $location) {
    if (file_exists($location . '/includes/functions.php')) {
        if (!defined('WP_TESTS_DIR')) {
            define('WP_TESTS_DIR', $location);
        }
        $wp_tests_found = true;
        break;
    }
}

// If WordPress test framework is available, use it
if ($wp_tests_found) {
    // Load WordPress test functions
    require_once WP_TESTS_DIR . '/includes/functions.php';
    
    // Set up test-specific filters
    function _oauth_passport_test_setup() {
        // Enable OAuth for tests
        add_filter('oauth_passport_enabled', '__return_true');
        
        // Set test-specific configuration
        add_filter('oauth_passport_access_token_lifetime', function() {
            return 3600; // 1 hour for tests
        });
        
        add_filter('oauth_passport_refresh_token_lifetime', function() {
            return 7200; // 2 hours for tests
        });
        
        add_filter('oauth_passport_authorization_code_lifetime', function() {
            return 600; // 10 minutes for tests
        });
        
        // Disable rate limiting for tests
        add_filter('oauth_passport_rate_limit_enabled', '__return_false');
        
        // Use faster hashing for tests
        add_filter('oauth_passport_hash_cost', function() {
            return 4; // Lower cost for faster tests
        });
    }
    
    function _manually_load_plugin() {
        // Set up test environment
        _oauth_passport_test_setup();
        
        // Load plugin
        require_once dirname(__DIR__) . '/oauth-passport.php';
        
        // Initialize the plugin
        if (function_exists('OAuthPassport\init_oauth_passport')) {
            OAuthPassport\init_oauth_passport();
        }
    }
    
    tests_add_filter('muplugins_loaded', '_manually_load_plugin');
    
    // Load WordPress bootstrap
    require_once WP_TESTS_DIR . '/includes/bootstrap.php';
    
    // Set up test database tables after WordPress is loaded
    function _oauth_passport_setup_test_tables() {
        // Ensure database tables are created
        if (class_exists('OAuthPassport\Auth\Schema')) {
            $schema = new OAuthPassport\Auth\Schema();
            $schema->create_tables();
        }
    }
    
    // Hook into WordPress init to set up tables
    add_action('init', '_oauth_passport_setup_test_tables', 1);
    
} else {
    // Fallback: Load WordPress directly and create minimal test framework
    
    // Load WordPress
    require_once ABSPATH . 'wp-config.php';
    require_once ABSPATH . 'wp-settings.php';
    
    // Set test mode to prevent REST API registration
    define('OAUTH_PASSPORT_TEST_MODE', true);
    
    // Load plugin
    require_once dirname(__DIR__) . '/oauth-passport.php';
    
    // Initialize the plugin but prevent REST API registration
    if (function_exists('OAuthPassport\init_oauth_passport')) {
        // Remove REST API initialization during tests
        remove_action('rest_api_init', 'OAuthPassport\init_oauth_passport');
        
        // Initialize plugin components without REST API
        OAuthPassport\init_oauth_passport();
    }
    
    // Create minimal test framework
    if (!class_exists('WP_UnitTestCase')) {
        class WP_UnitTestCase extends PHPUnit\Framework\TestCase {
            protected $factory;
            
            public function setUp(): void {
                parent::setUp();
                
                // Create a minimal factory for user creation
                $this->factory = new stdClass();
                $this->factory->user = new class {
                    public function create($args = []) {
                        // Generate unique identifiers
                        $unique_id = uniqid('test_', true) . '_' . mt_rand(1000, 9999);
                        
                        $defaults = [
                            'user_login' => 'testuser_' . $unique_id,
                            'user_email' => 'test_' . $unique_id . '@example.com',
                            'user_pass' => 'password123',
                            'role' => 'subscriber'
                        ];
                        
                        $user_data = wp_parse_args($args, $defaults);
                        
                        // Ensure unique username
                        $counter = 0;
                        $original_login = $user_data['user_login'];
                        while (username_exists($user_data['user_login']) && $counter < 100) {
                            $counter++;
                            $user_data['user_login'] = $original_login . '_' . $counter;
                        }
                        
                        // Ensure unique email
                        $counter = 0;
                        $original_email = $user_data['user_email'];
                        while (email_exists($user_data['user_email']) && $counter < 100) {
                            $counter++;
                            $user_data['user_email'] = str_replace('@', '_' . $counter . '@', $original_email);
                        }
                        
                        $user_id = wp_insert_user($user_data);
                        
                        if (is_wp_error($user_id)) {
                            throw new Exception('Failed to create test user: ' . $user_id->get_error_message());
                        }
                        
                        // Mark as test user for cleanup
                        update_user_meta($user_id, 'oauth_test_user', '1');
                        
                        return $user_id;
                    }
                };
            }
            
            public function tearDown(): void {
                parent::tearDown();
                
                // Clean up test data
                global $wpdb;
                $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_clients WHERE client_id LIKE '%test_%'");
                $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_tokens WHERE client_id LIKE '%test_%'");
            }
        }
    }
    
    // Set up database tables
    if (class_exists('OAuthPassport\Auth\Schema')) {
        $schema = new OAuthPassport\Auth\Schema();
        $schema->create_tables();
    }
}

// Clean up function for tests
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

// Register shutdown function to clean up
register_shutdown_function('oauth_passport_cleanup_test_data');
