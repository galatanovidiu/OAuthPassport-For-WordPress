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
	 * Current schema version
	 *
	 * Increment this when making schema changes that require migration.
	 */
	private const SCHEMA_VERSION = 2;

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

		// Use different column types based on database type
		$token_type_column = $this->is_sqlite() 
			? "token_type VARCHAR(20) NOT NULL CHECK (token_type IN ('code', 'access', 'registration', 'refresh'))"
			: "token_type ENUM('code', 'access', 'registration', 'refresh') NOT NULL";

	$sql = "CREATE TABLE IF NOT EXISTS {$this->tokens_table} (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		{$token_type_column},
		token_value VARCHAR(255) UNIQUE NOT NULL,
		client_id VARCHAR(255) NOT NULL,
		user_id BIGINT NOT NULL,
		code_challenge VARCHAR(255),
		scope VARCHAR(255),
		resource VARCHAR(500),
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		token_version VARCHAR(10) DEFAULT '2.0',
		INDEX idx_token (token_value),
		INDEX idx_expires (expires_at),
		INDEX idx_client_user (client_id, user_id),
		INDEX idx_version (token_version),
		INDEX idx_resource (resource),
		INDEX idx_type_expires (token_type, expires_at)
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
		client_secret_hash VARCHAR(255),
		client_name VARCHAR(255) NOT NULL,
		redirect_uris TEXT NOT NULL,
		grant_types TEXT,
		response_types TEXT,
		scope TEXT,
		allowed_resources TEXT,
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
		is_confidential BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
		secret_version VARCHAR(10) DEFAULT '2.0',
		INDEX idx_client_id (client_id),
		INDEX idx_registration_token (registration_access_token),
		INDEX idx_secret_version (secret_version)
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
	 * Get current schema version from database
	 *
	 * @return int Current schema version
	 */
	public function get_current_version(): int {
		return (int) get_option( 'oauth_passport_schema_version', 1 );
	}

	/**
	 * Update schema version in database
	 *
	 * @param int $version New schema version
	 */
	private function update_version( int $version ): void {
		update_option( 'oauth_passport_schema_version', $version );
	}

	/**
	 * Check if migration is needed and run it
	 *
	 * @return bool True if migration was performed
	 */
	public function maybe_migrate(): bool {
		$current_version = $this->get_current_version();

		if ( $current_version >= self::SCHEMA_VERSION ) {
			return false; // Already up to date
		}

		// Run migrations
		if ( $current_version < 2 ) {
			$this->migrate_to_v2();
		}

		return true;
	}

	/**
	 * Migrate to version 2: Add resource columns
	 *
	 * Adds resource support for RFC 8707 (Resource Indicators)
	 */
	private function migrate_to_v2(): void {
		global $wpdb;

		// Add resource column to tokens table
		$tokens_table = esc_sql( $this->tokens_table );
		
		// Check if column exists
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$column_exists = $wpdb->get_results(
			$wpdb->prepare(
				"SHOW COLUMNS FROM {$tokens_table} LIKE %s",
				'resource'
			)
		);

		if ( empty( $column_exists ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
			$wpdb->query(
				"ALTER TABLE {$tokens_table} ADD COLUMN resource VARCHAR(500) AFTER scope"
			);

			// Add index
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
			$wpdb->query(
				"ALTER TABLE {$tokens_table} ADD INDEX idx_resource (resource)"
			);

			// Add composite index for cleanup queries
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
			$wpdb->query(
				"ALTER TABLE {$tokens_table} ADD INDEX idx_type_expires (token_type, expires_at)"
			);
		}

		// Add allowed_resources column to clients table
		$clients_table = esc_sql( $this->clients_table );
		
		// Check if column exists
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$column_exists = $wpdb->get_results(
			$wpdb->prepare(
				"SHOW COLUMNS FROM {$clients_table} LIKE %s",
				'allowed_resources'
			)
		);

		if ( empty( $column_exists ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
			$wpdb->query(
				"ALTER TABLE {$clients_table} ADD COLUMN allowed_resources TEXT AFTER scope"
			);
		}

		// Update version
		$this->update_version( 2 );

		// Log successful migration
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( '[OAuth Passport] Successfully migrated schema to version 2 (Resource Indicators support)' );
		}
	}

	/**
	 * Drop the OAuth tables
	 */
	public function drop_tables(): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$tokens_table  = esc_sql( $this->tokens_table );
		$clients_table = esc_sql( $this->clients_table );

		$wpdb->query( "DROP TABLE IF EXISTS {$tokens_table}" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$wpdb->query( "DROP TABLE IF EXISTS {$clients_table}" );
	}

	/**
	 * Clean up expired tokens
	 *
	 * @return int Number of deleted tokens
	 */
	public function cleanup_expired_tokens(): int {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$table = esc_sql( $this->tokens_table );

		$deleted = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE expires_at < %s",
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
	 * Check if we're using SQLite
	 *
	 * @return bool True if using SQLite, false otherwise.
	 */
	private function is_sqlite(): bool {
		global $wpdb;
		
		// Check if we're using SQLite integration plugin
		if ( defined( 'DATABASE_TYPE' ) && 'sqlite' === constant( 'DATABASE_TYPE' ) ) {
			return true;
		}
		
		// Check if wpdb is using SQLite
		if ( method_exists( $wpdb, 'db_version' ) ) {
			$version = $wpdb->db_version();
			return false !== stripos( $version, 'sqlite' );
		}
		
		// Check the database class
		return false !== stripos( get_class( $wpdb ), 'sqlite' );
	}
} 
