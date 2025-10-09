<?php
/**
 * OAuth Authorization Consent Form View
 *
 * Displays the user consent page for OAuth authorization requests.
 * This is shown to users when an application requests access to their account.
 *
 * @package OAuthPassport
 * @subpackage Admin\Views
 */

declare( strict_types=1 );

namespace OAuthPassport\Admin\Views;

use OAuthPassport\Auth\ScopeManager;

/**
 * Render OAuth authorization consent form
 *
 * @param object|null  $client Client details
 * @param string       $redirect_uri Redirect URI
 * @param string       $code_challenge PKCE code challenge
 * @param string|null  $state State parameter
 * @param string       $scope Requested scope
 * @param ScopeManager $scope_manager Scope manager instance
 */
function render_authorization_form( ?object $client, string $redirect_uri, string $code_challenge, ?string $state, string $scope, ScopeManager $scope_manager ): void {
	$scopes = explode( ' ', $scope );
	$current_user = wp_get_current_user();

	// Set proper headers
	status_header( 200 );
	header( 'Content-Type: text/html; charset=utf-8' );
	?>
	<!DOCTYPE html>
	<html <?php language_attributes(); ?>>
	<head>
		<meta charset="<?php bloginfo( 'charset' ); ?>">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title><?php esc_html_e( 'Authorize Application', 'oauth-passport' ); ?> - <?php bloginfo( 'name' ); ?></title>
		<?php wp_admin_css( 'login', true ); ?>
		<style>
			body {
				background: #f0f0f1;
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
			}
			.oauth-container {
				margin: 50px auto;
				max-width: 500px;
				background: #fff;
				box-shadow: 0 1px 3px rgba(0,0,0,.13);
				padding: 40px;
			}
			.oauth-header {
				text-align: center;
				margin-bottom: 40px;
			}
			.oauth-logo {
				max-width: 84px;
				margin: 0 auto 20px;
			}
			.oauth-title {
				font-size: 24px;
				margin: 0 0 10px;
				color: #3c434a;
			}
			.oauth-subtitle {
				color: #646970;
				font-size: 14px;
			}
			.oauth-client-info {
				background: #f6f7f7;
				border: 1px solid #c3c4c7;
				padding: 20px;
				margin-bottom: 30px;
				border-radius: 4px;
			}
			.oauth-client-name {
				font-weight: 600;
				font-size: 16px;
				margin-bottom: 10px;
			}
			.oauth-permissions {
				margin-bottom: 30px;
			}
			.oauth-permissions-title {
				font-weight: 600;
				margin-bottom: 15px;
				color: #1d2327;
			}
			.oauth-permission-list {
				list-style: none;
				padding: 0;
				margin: 0;
			}
			.oauth-permission-item {
				padding: 10px 0;
				padding-left: 30px;
				position: relative;
				color: #50575e;
			}
			.oauth-permission-item:before {
				content: "✓";
				position: absolute;
				left: 0;
				color: #00a32a;
				font-weight: bold;
			}
			.oauth-actions {
				display: flex;
				gap: 10px;
				justify-content: center;
			}
			.oauth-button {
				padding: 10px 30px;
				font-size: 14px;
				border-radius: 3px;
				border: 1px solid;
				cursor: pointer;
				text-decoration: none;
				transition: all 0.3s;
			}
			.oauth-button-primary {
				background: #2271b1;
				border-color: #2271b1;
				color: #fff;
			}
			.oauth-button-primary:hover {
				background: #135e96;
				border-color: #135e96;
			}
			.oauth-button-secondary {
				background: #f0f0f1;
				border-color: #c3c4c7;
				color: #2c3338;
			}
			.oauth-button-secondary:hover {
				background: #e5e5e5;
			}
			.oauth-user-info {
				text-align: center;
				margin-bottom: 20px;
				color: #646970;
				font-size: 14px;
			}
			.oauth-warning {
				background: #fcf9e8;
				border: 1px solid #dfd8c2;
				padding: 15px;
				margin-bottom: 20px;
				border-radius: 4px;
				color: #50575e;
				font-size: 14px;
			}
		</style>
	</head>
	<body>
		<div class="oauth-container">
			<div class="oauth-header">
				<div class="oauth-logo">
					<?php
					$custom_logo_id = get_theme_mod( 'custom_logo' );
					if ( $custom_logo_id ) {
						echo wp_get_attachment_image( $custom_logo_id, 'thumbnail' );
					} else {
						echo '<img src="' . esc_url( includes_url( 'images/w-logo-blue.png' ) ) . '" alt="WordPress">';
					}
					?>
				</div>
				<h1 class="oauth-title"><?php esc_html_e( 'Authorize Application', 'oauth-passport' ); ?></h1>
				<p class="oauth-subtitle"><?php esc_html_e( 'An application is requesting access to your account', 'oauth-passport' ); ?></p>
			</div>

			<div class="oauth-user-info">
				<?php
				printf(
					/* translators: %s: username */
					esc_html__( 'Logged in as %s', 'oauth-passport' ),
					'<strong>' . esc_html( $current_user->user_login ) . '</strong>'
				);
				?>
			</div>

			<div class="oauth-client-info">
				<div class="oauth-client-name">
					<?php echo esc_html( $client->client_name ?? __( 'Unknown Application', 'oauth-passport' ) ); ?>
				</div>
				<?php if ( ! empty( $client->client_uri ) ) : ?>
					<div class="oauth-client-uri">
						<a href="<?php echo esc_url( $client->client_uri ); ?>" target="_blank" rel="noopener noreferrer">
							<?php echo esc_html( wp_parse_url( $client->client_uri, PHP_URL_HOST ) ?: $client->client_uri ); ?>
						</a>
					</div>
				<?php endif; ?>
			</div>

			<div class="oauth-permissions">
				<div class="oauth-permissions-title"><?php esc_html_e( 'This application will be able to:', 'oauth-passport' ); ?></div>
				<ul class="oauth-permission-list">
					<?php
					$available_scopes = $scope_manager->getAvailableScopes();
					foreach ( $scopes as $scope_key ) {
						if ( isset( $available_scopes[ $scope_key ] ) ) {
							echo '<li class="oauth-permission-item">' . esc_html( $available_scopes[ $scope_key ] ) . '</li>';
						}
					}
					?>
				</ul>
			</div>

			<div class="oauth-warning">
				<?php esc_html_e( 'Make sure you trust this application before authorizing. You can revoke access at any time from your account settings.', 'oauth-passport' ); ?>
			</div>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<?php wp_nonce_field( 'oauth_authorize' ); ?>
				<input type="hidden" name="action" value="oauth_passport_authorize">
				<input type="hidden" name="client_id" value="<?php echo esc_attr( sanitize_text_field( wp_unslash( $_GET['client_id'] ?? '' ) ) ); ?>">
				<input type="hidden" name="redirect_uri" value="<?php echo esc_attr( $redirect_uri ); ?>">
				<input type="hidden" name="code_challenge" value="<?php echo esc_attr( $code_challenge ); ?>">
				<input type="hidden" name="code_challenge_method" value="S256">
				<input type="hidden" name="state" value="<?php echo esc_attr( $state ?? '' ); ?>">
				<input type="hidden" name="scope" value="<?php echo esc_attr( $scope ); ?>">
				<input type="hidden" name="resource" value="<?php echo esc_attr( sanitize_text_field( wp_unslash( $_GET['resource'] ?? '' ) ) ); ?>">

				<div class="oauth-actions">
					<button type="submit" name="oauth_action" value="allow" class="oauth-button oauth-button-primary">
						<?php esc_html_e( 'Authorize', 'oauth-passport' ); ?>
					</button>
					<button type="submit" name="oauth_action" value="deny" class="oauth-button oauth-button-secondary">
						<?php esc_html_e( 'Deny', 'oauth-passport' ); ?>
					</button>
				</div>
			</form>
		</div>
	</body>
	</html>
	<?php
	exit;
}

