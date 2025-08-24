<?php
/**
 * OAuth Admin Interface for OAuth Passport
 *
 * Provides WordPress admin interface for OAuth client and token management.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

use JetBrains\PhpStorm\NoReturn;

/**
 * Class AdminInterface
 *
 * WordPress admin interface for OAuth management.
 */
class AdminInterface {
	/**
	 * Schema instance
	 *
	 * @var Schema
	 */
	private Schema $schema;

	/**
	 * Scope manager instance
	 *
	 * @var ScopeManager
	 */
	private ScopeManager $scope_manager;

	/**
	 * Constructor
	 */
	public function __construct() {
		$this->schema        = new Schema();
		$this->scope_manager = new ScopeManager();

		// Add admin hooks.
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_assets' ) );

		// Add admin actions.
		add_action( 'admin_post_oauth_passport_revoke_oauth_client', array( $this, 'handle_revoke_client' ) );
		add_action( 'admin_post_oauth_passport_revoke_oauth_token', array( $this, 'handle_revoke_token' ) );
		add_action( 'admin_post_oauth_passport_generate_oauth_client', array( $this, 'handle_generate_client' ) );
	}

	/**
	 * Add admin menu items
	 */
	public function add_admin_menu(): void {
		// Main OAuth page.
		add_submenu_page(
			'options-general.php',
			'OAuth Passport',
			'OAuth Passport',
			'manage_options',
			'oauth-passport',
			array( $this, 'render_admin_page' )
		);
	}

	/**
	 * Register settings
	 */
	public function register_settings(): void {
		register_setting(
			'oauth_passport_settings',
			'oauth_passport_enabled',
			array(
				'type'              => 'boolean',
				'default'           => true,
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);

		register_setting(
			'oauth_passport_settings',
			'oauth_passport_access_token_lifetime',
			array(
				'type'              => 'integer',
				'default'           => 3600,
				'sanitize_callback' => 'absint',
			)
		);

		register_setting(
			'oauth_passport_settings',
			'oauth_passport_refresh_token_lifetime',
			array(
				'type'              => 'integer',
				'default'           => 2592000, // 30 days.
				'sanitize_callback' => 'absint',
			)
		);
	}

	/**
	 * Enqueue admin assets
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue_admin_assets( string $hook ): void {
		// Only load on our pages.
		if ( ! in_array( $hook, array( 'settings_page_oauth-passport', 'admin_page_oauth-passport-clients', 'admin_page_oauth-passport-tokens' ), true ) ) {
			return;
		}

		// Get asset file for dependencies and version.
		$asset_file_path = OAUTH_PASSPORT_PATH . 'build/index.asset.php';
		$asset_file = false;

		if ( file_exists( $asset_file_path ) ) {
			$asset_file = include $asset_file_path;
		}

		if ( ! $asset_file || ! is_array( $asset_file ) ) {
			$asset_file = array(
				'dependencies' => array( 'wp-element', 'wp-i18n', 'wp-components', 'wp-api-fetch' ),
				'version'      => '1.0.0',
			);
		}

		// Enqueue React admin app.
		wp_enqueue_script(
			'oauth-passport-admin',
			OAUTH_PASSPORT_URL . 'build/index.js',
			$asset_file['dependencies'],
			$asset_file['version'],
			true
		);

		wp_enqueue_style(
			'oauth-passport-admin',
			OAUTH_PASSPORT_URL . 'build/style-index.css',
			array( 'wp-components' ),
			$asset_file['version']
		);

		// Localize script for API endpoints.
		wp_localize_script(
			'oauth-passport-admin',
			'oauthPassportAdmin',
			array(
				'apiUrl'    => rest_url( 'oauth-passport/v1/' ),
				'nonce'     => wp_create_nonce( 'wp_rest' ),
				'adminUrl'  => admin_url( 'admin.php?page=oauth-passport' ),
			)
		);
	}

	/**
	 * Render main admin page
	 */
	public function render_admin_page(): void {
		?>
		<div class="wrap">
			<div id="oauth-passport-admin-root">
				<!-- React app will render here -->
			</div>
		</div>
		<?php
	}

	/**
	 * Render clients page
	 */
	#[NoReturn]
    public function render_clients_page(): void {
		// Redirect to the main page since we use tabs in React app.
		wp_redirect( admin_url( 'admin.php?page=oauth-passport#clients' ) );
		exit;
	}

	/**
	 * Render tokens page
	 */
	#[NoReturn]
    public function render_tokens_page(): void {
		// Redirect to main page since we use tabs in React app.
		wp_redirect( admin_url( 'admin.php?page=oauth-passport#tokens' ) );
		exit;
	}

	/**
	 * Handle revoke client action
	 */
	#[NoReturn]
    public function handle_revoke_client(): void {
		$client_id = sanitize_text_field( wp_unslash( $_GET['client_id'] ?? '' ) );

		if ( ! $client_id || ! check_admin_referer( 'oauth_passport_revoke_oauth_client_' . $client_id ) ) {
			wp_die( 'Invalid request' );
		}

		global $wpdb;
		$clients_table = $this->schema->get_clients_table_name();
		$tokens_table  = $this->schema->get_table_name();

		// Delete all tokens for this client.
		$wpdb->delete( $tokens_table, array( 'client_id' => $client_id ) );

		// Delete client.
		$wpdb->delete( $clients_table, array( 'client_id' => $client_id ) );

		wp_redirect( admin_url( 'admin.php?page=oauth-passport-clients&revoked=1' ) );
		exit;
	}

	/**
	 * Handle revoke token action
	 */
	#[NoReturn]
    public function handle_revoke_token(): void {
		$token_id = absint( $_GET['token_id'] ?? 0 );

		if ( ! $token_id || ! check_admin_referer( 'oauth_passport_revoke_oauth_token_' . $token_id ) ) {
			wp_die( 'Invalid request' );
		}

		global $wpdb;
		$table = $this->schema->get_table_name();

		$wpdb->delete( $table, array( 'id' => $token_id ) );

		wp_redirect( admin_url( 'admin.php?page=oauth-passport-tokens&revoked=1' ) );
		exit;
	}

	/**
	 * Handle generate client action
	 */
	#[NoReturn]
    public function handle_generate_client(): void {
		if ( ! check_admin_referer( 'oauth_passport_generate_oauth_client' ) ) {
			wp_die( 'Invalid request' );
		}

		$client_name  = sanitize_text_field( wp_unslash( $_POST['client_name'] ?? '' ) );
		$redirect_uri = esc_url_raw( wp_unslash( $_POST['redirect_uri'] ?? '' ) );
		$scopes       = array_map( 'sanitize_text_field', wp_unslash( $_POST['scopes'] ?? array() ) );

		if ( ! $client_name || ! $redirect_uri ) {
			wp_die( 'Client name and redirect URI are required' );
		}

		// Generate client credentials.
		$client_id     = 'oauth_passport_' . wp_generate_password( 32, false );
		$client_secret = wp_generate_password( 64, false );

		// Store client.
		global $wpdb;
		$table = $this->schema->get_clients_table_name();

		$wpdb->insert(
			$table,
			array(
				'client_id'                 => $client_id,
				'client_secret_hash'             => wp_hash( $client_secret ),
				'client_name'               => $client_name,
				'redirect_uris'             => wp_json_encode( array( $redirect_uri ) ),
				'grant_types'               => wp_json_encode( array( 'authorization_code' ) ),
				'response_types'            => wp_json_encode( array( 'code' ) ),
				'scope'                     => implode( ' ', $scopes ),
				'token_endpoint_auth_method' => 'client_secret_post',
				'client_id_issued_at'       => time(),
				'client_secret_expires_at'  => 0,
			)
		);

		// Store credentials temporarily in transient to display once.
		set_transient(
			'oauth_passport_new_client_' . get_current_user_id(),
			array(
				'client_id'     => $client_id,
				'client_secret' => $client_secret,
			),
			60
		);

		wp_redirect( admin_url( 'admin.php?page=oauth-passport-clients&generated=1' ) );
		exit;
	}
}
