<?php
/**
 * OAuth Error Logger for OAuth Passport
 *
 * Provides enhanced error handling and logging for OAuth operations.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

/**
 * Class ErrorLogger
 *
 * Handles OAuth error logging and reporting.
 */
class ErrorLogger {
	/**
	 * Log table name
	 *
	 * @var string
	 */
	private string $log_table;

	/**
	 * Constructor
	 */
	public function __construct() {
		global $wpdb;
		$this->log_table = $wpdb->prefix . 'oauth_passport_logs';

		// Initialize logging.
		add_action( 'init', array( $this, 'maybe_create_log_table' ) );

		// Clean up old logs.
		if ( ! wp_next_scheduled( 'oauth_passport_cleanup_logs' ) ) {
			wp_schedule_event( time(), 'daily', 'oauth_passport_cleanup_logs' );
		}
		add_action( 'oauth_passport_cleanup_logs', array( $this, 'cleanup_old_logs' ) );
	}

	/**
	 * Create log table if needed
	 */
	public function maybe_create_log_table(): void {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE IF NOT EXISTS {$this->log_table} (
			id BIGINT AUTO_INCREMENT PRIMARY KEY,
			event_type VARCHAR(50) NOT NULL,
			event_subtype VARCHAR(50),
			client_id VARCHAR(255),
			user_id BIGINT,
			ip_address VARCHAR(45),
			user_agent TEXT,
			error_code VARCHAR(50),
			error_message TEXT,
			additional_data TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_event_type (event_type),
			INDEX idx_client_id (client_id),
			INDEX idx_user_id (user_id),
			INDEX idx_created_at (created_at)
		) $charset_collate";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Log an OAuth event
	 *
	 * @param string $event_type Event type (e.g., 'authorization', 'token', 'error').
	 * @param array  $data Event data.
	 */
	public function log_event( string $event_type, array $data = array() ): void {
		global $wpdb;

		// Prepare log entry.
		$log_entry = array(
			'event_type'      => $event_type,
			'event_subtype'   => $data['subtype'] ?? null,
			'client_id'       => $data['client_id'] ?? null,
			'user_id'         => $data['user_id'] ?? get_current_user_id(),
			'ip_address'      => $this->get_client_ip(),
			'user_agent'      => $this->get_user_agent(),
			'error_code'      => $data['error_code'] ?? null,
			'error_message'   => $data['error_message'] ?? null,
			'additional_data' => ! empty( $data['additional'] ) ? wp_json_encode( $data['additional'] ) : null,
		);

		// Insert log entry.
		$wpdb->insert( $this->log_table, $log_entry );

		// Also log to WordPress debug.log if WP_DEBUG_LOG is enabled.
		if ( defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			error_log(
				sprintf(
					'[OAuth Passport] %s: %s',
					$event_type,
					wp_json_encode( $log_entry )
				)
					);
	}
}

	/**
	 * Log authorization attempt
	 *
	 * @param string $client_id Client ID.
	 * @param bool   $success Whether authorization was successful.
	 * @param string $error Error message if failed.
	 */
	public function log_authorization( string $client_id, bool $success, string $error = '' ): void {
		$this->log_event(
			'authorization',
			array(
				'subtype'       => $success ? 'success' : 'failure',
				'client_id'     => $client_id,
				'error_message' => $error,
			)
		);
	}

	/**
	 * Log token generation
	 *
	 * @param string $client_id Client ID.
	 * @param string $grant_type Grant type used.
	 * @param bool   $success Whether token generation was successful.
	 * @param string $error Error message if failed.
	 */
	public function log_token_generation( string $client_id, string $grant_type, bool $success, string $error = '' ): void {
		$this->log_event(
			'token',
			array(
				'subtype'       => $grant_type,
				'client_id'     => $client_id,
				'error_message' => $error,
				'additional'    => array(
					'success' => $success,
				),
			)
		);
	}

	/**
	 * Log client registration
	 *
	 * @param string $client_id Client ID.
	 * @param bool   $success Whether registration was successful.
	 * @param array  $metadata Client metadata.
	 */
	public function log_client_registration( string $client_id, bool $success, array $metadata = array() ): void {
		$this->log_event(
			'registration',
			array(
				'subtype'    => $success ? 'success' : 'failure',
				'client_id'  => $client_id,
				'additional' => $metadata,
			)
		);
	}

	/**
	 * Log rate limit violation
	 *
	 * @param string $identifier Rate limit identifier (IP, client_id, etc.).
	 * @param string $limit_type Type of limit hit.
	 */
	public function log_rate_limit( string $identifier, string $limit_type ): void {
		$this->log_event(
			'rate_limit',
			array(
				'subtype'       => $limit_type,
				'error_code'    => 'rate_limit_exceeded',
				'error_message' => 'Rate limit exceeded for ' . $limit_type,
				'additional'    => array(
					'identifier' => $identifier,
				),
			)
		);
	}

	/**
	 * Get recent logs
	 *
	 * @param array $args Query arguments.
	 * @return array Log entries.
	 */
	public function get_logs( array $args = array() ): array {
		global $wpdb;

		$defaults = array(
			'event_type' => '',
			'client_id'  => '',
			'user_id'    => 0,
			'limit'      => 100,
			'offset'     => 0,
			'order'      => 'DESC',
		);

		$args = wp_parse_args( $args, $defaults );

		$where_clauses = array( '1=1' );
		$where_values  = array();

		if ( ! empty( $args['event_type'] ) ) {
			$where_clauses[] = 'event_type = %s';
			$where_values[]  = $args['event_type'];
		}

		if ( ! empty( $args['client_id'] ) ) {
			$where_clauses[] = 'client_id = %s';
			$where_values[]  = $args['client_id'];
		}

		if ( ! empty( $args['user_id'] ) ) {
			$where_clauses[] = 'user_id = %d';
			$where_values[]  = $args['user_id'];
		}

		$where_sql = implode( ' AND ', $where_clauses );
		$order_sql = 'DESC' === strtoupper( $args['order'] ) ? 'DESC' : 'ASC';

		// Build query.
		$prepare_values = array_merge(
			array( $this->log_table ),
			$where_values,
			array( $args['limit'], $args['offset'] )
		);

		$query = $wpdb->prepare(
			"SELECT * FROM %i WHERE {$where_sql} ORDER BY created_at {$order_sql} LIMIT %d OFFSET %d",
			...$prepare_values
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		return $wpdb->get_results( $query, ARRAY_A );
	}

	/**
	 * Get error statistics
	 *
	 * @param int $days Number of days to look back.
	 * @return array Error statistics.
	 */
	public function get_error_statistics( int $days = 7 ): array {
		global $wpdb;

		$since = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT 
					event_type,
					event_subtype,
					error_code,
					COUNT(*) as count
				FROM %i
				WHERE created_at > %s
				AND error_code IS NOT NULL
				GROUP BY event_type, event_subtype, error_code
				ORDER BY count DESC",
				$this->log_table,
				$since
			),
			ARRAY_A
		);
	}

	/**
	 * Clean up old logs
	 */
	public function cleanup_old_logs(): void {
		global $wpdb;

		// Keep logs for 30 days by default.
		$retention_days = apply_filters( 'oauth_passport_log_retention_days', 30 );
		$cutoff_date    = gmdate( 'Y-m-d H:i:s', strtotime( "-{$retention_days} days" ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM %i WHERE created_at < %s",
				$this->log_table,
				$cutoff_date
			)
		);
	}

	/**
	 * Get client IP address
	 *
	 * @return string IP address.
	 */
	private function get_client_ip(): string {
		$ip_keys = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR' );

		foreach ( $ip_keys as $key ) {
			if ( array_key_exists( $key, $_SERVER ) === true ) {
				foreach ( explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ) ) as $ip ) {
					$ip = trim( $ip );

					if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
						return $ip;
					}
				}
			}
		}

		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}

	/**
	 * Get user agent
	 *
	 * @return string User agent string.
	 */
	private function get_user_agent(): string {
		return substr( isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '', 0, 255 );
	}

	/**
	 * Format error response with logging
	 *
	 * @param string $error_code OAuth error code.
	 * @param string $error_description Human-readable error description.
	 * @param array  $additional_data Additional context data.
	 * @return \WP_Error
	 */
	public function create_error( string $error_code, string $error_description, array $additional_data = array() ): \WP_Error {
		// Log the error.
		$this->log_event(
			'error',
			array(
				'error_code'    => $error_code,
				'error_message' => $error_description,
				'additional'    => $additional_data,
			)
		);

		// Create WP_Error with proper OAuth format.
		return new \WP_Error(
			$error_code,
			$error_description,
			array_merge(
				array( 'status' => 400 ),
				$additional_data
			)
		);
	}
} 