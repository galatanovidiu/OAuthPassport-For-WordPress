<?php
/**
 * OAuth 2.1 Database Schema
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

/**
 * Class Schema
 *
 * Handles database schema creation and management for OAuth tokens and clients.
 */
class Schema {
	/**
	 * Tokens table name
	 *
	 * @var string
	 */
	private string $tokens_table;

	/**
	 * Clients table name
	 *
	 * @var string
	 */
	private string $clients_table;

	/**
	 * Constructor
	 */
	public function __construct() {
		global $wpdb;
		$this->tokens_table  = $wpdb->prefix . 'oauth_passport_tokens';
		$this->clients_table = $wpdb->prefix . 'oauth_passport_clients';
	}

	/**
	 * Get the tokens table name
	 *
	 * @return string
	 */
	public function get_table_name(): string {
		return $this->tokens_table;
	}

	/**
	 * Get the clients table name
	 *
	 * @return string
	 */
	public function get_clients_table_name(): string {
		return $this->clients_table;
	}

	/**
	 * Create the OAuth tables
	 */
	public function create_tables(): void {
		$this->create_tokens_table();
		$this->create_clients_table();
	}

	/**
	 * Create the OAuth tokens table
	 */
	private function create_tokens_table(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$this->tokens_table} (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			token_type ENUM('code', 'access', 'registration', 'refresh') NOT NULL,
			token_value VARCHAR(255) UNIQUE NOT NULL,
			client_id VARCHAR(255) NOT NULL,
			user_id BIGINT NOT NULL,
			code_challenge VARCHAR(255),
			scope VARCHAR(255),
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_token (token_value),
			INDEX idx_expires (expires_at),
			INDEX idx_client_user (client_id, user_id)
		) $charset_collate";

		dbDelta( $sql );
	}

	/**
	 * Create the OAuth clients table
	 */
	private function create_clients_table(): void {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$this->clients_table} (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			client_id VARCHAR(255) UNIQUE NOT NULL,
			client_secret VARCHAR(255),
			client_name VARCHAR(255) NOT NULL,
			redirect_uris TEXT NOT NULL,
			grant_types TEXT,
			response_types TEXT,
			scope TEXT,
			contacts TEXT,
			logo_uri VARCHAR(500),
			client_uri VARCHAR(500),
			policy_uri VARCHAR(500),
			tos_uri VARCHAR(500),
			jwks_uri VARCHAR(500),
			token_endpoint_auth_method VARCHAR(50),
			registration_access_token VARCHAR(255),
			registration_client_uri VARCHAR(500),
			client_id_issued_at BIGINT,
			client_secret_expires_at BIGINT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_client_id (client_id),
			INDEX idx_registration_token (registration_access_token)
		) $charset_collate";

		dbDelta( $sql );
	}

	/**
	 * Create tables (backward compatibility)
	 */
	public function create_table(): void {
		$this->create_tables();
	}

	/**
	 * Drop the OAuth tables
	 */
	public function drop_tables(): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $this->tokens_table ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $this->clients_table ) );
	}

	/**
	 * Clean up expired tokens
	 *
	 * @return int Number of deleted tokens
	 */
	public function cleanup_expired_tokens(): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$deleted = $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE expires_at < %s',
				$this->tokens_table,
				current_time( 'mysql' )
			)
		);

		return $deleted ? $deleted : 0;
	}

	/**
	 * Check if the tables exist
	 *
	 * @return bool
	 */
	public function table_exists(): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$tokens_exist = $wpdb->get_var(
			$wpdb->prepare(
				'SHOW TABLES LIKE %s',
				$this->tokens_table
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$clients_exist = $wpdb->get_var(
			$wpdb->prepare(
				'SHOW TABLES LIKE %s',
				$this->clients_table
			)
		);

		return $tokens_exist === $this->tokens_table && $clients_exist === $this->clients_table;
	}

	/**
	 * Upgrade database schema for refresh token support
	 */
	public function upgrade_schema(): void {
		global $wpdb;

		// Check if refresh token type already exists.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$column_info = $wpdb->get_results(
			$wpdb->prepare(
				"SHOW COLUMNS FROM %i WHERE Field = 'token_type'",
				$this->tokens_table
			)
		);

		if ( ! empty( $column_info ) && false === strpos( $column_info[0]->Type, 'refresh' ) ) {
			// Add refresh to the enum.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
			$wpdb->query(
				$wpdb->prepare(
					"ALTER TABLE %i MODIFY token_type ENUM('code', 'access', 'registration', 'refresh') NOT NULL",
					$this->tokens_table
				)
			);
		}

		// Check if scope column exists.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$scope_exists = $wpdb->get_var(
			$wpdb->prepare(
				"SHOW COLUMNS FROM %i LIKE 'scope'",
				$this->tokens_table
			)
		);

		if ( ! $scope_exists ) {
			// Add scope column.
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
			$wpdb->query(
				$wpdb->prepare(
					'ALTER TABLE %i ADD COLUMN scope VARCHAR(255) AFTER code_challenge',
					$this->tokens_table
				)
			);
		}
	}
} 