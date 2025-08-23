=== OAuth Passport ===
Contributors: galatanovidiu
Tags: oauth, oauth2, authentication, api, rest-api, security, authorization, token, pkce, jwt
Requires at least: 6.4
Tested up to: 6.7
Requires PHP: 8.0
Stable tag: 1.0.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Transform your WordPress site into a secure OAuth 2.1 authorization server. Enable third-party applications to authenticate users and access your APIs through standards-compliant OAuth flows.

== Description ==

OAuth Passport transforms your WordPress site into a fully-featured **OAuth 2.1 authorization server**. It allows external applications to authenticate users and access your WordPress resources through secure, standards-compliant OAuth flows.

Whether you're building a mobile app, desktop application, or integrating with third-party services, OAuth Passport provides the authentication infrastructure you need.

= Key Features =

* **OAuth 2.1 Compliant** - Full implementation with mandatory PKCE support
* **Dynamic Client Registration** - RFC 7591 compliant self-service client registration
* **Client Management** - RFC 7592 compliant configuration management
* **Secure Token Storage** - Database-backed tokens with automatic cleanup
* **Admin Interface** - Comprehensive WordPress admin panel for OAuth management
* **Flexible Scopes** - Fine-grained permission system
* **JWKS Support** - JSON Web Key Set endpoint for token validation
* **Discovery Endpoints** - OpenID Connect-style discovery for easy integration
* **WordPress Integration** - Works seamlessly with WordPress user system
* **REST API Compatible** - Protects any WordPress REST API endpoint

= Use Cases =

* **Mobile Apps** - Authenticate users in iOS/Android apps
* **Desktop Applications** - Secure authentication for desktop software
* **Third-party Integrations** - Allow external services to access your API
* **Single Sign-On (SSO)** - Use WordPress as the identity provider
* **API Access Control** - Manage who can access your REST APIs
* **Partner Integrations** - Provide secure access to business partners
* **Plugin Development** - Add OAuth support to your WordPress plugins
* **AI Integration** - Enable AI assistants to securely access WordPress data

= Security Features =

* **PKCE Required** - Protects against authorization code interception
* **Token Rotation** - Refresh tokens are rotated on use
* **Secure Storage** - All secrets are properly hashed
* **HTTPS Enforcement** - Required in production environments
* **Rate Limiting** - Protects against brute force attacks
* **Event Logging** - Comprehensive audit trail

= Developer Friendly =

OAuth Passport provides helper functions and WordPress filters for easy integration:

* `oauth_passport_get_current_token()` - Get current OAuth token
* `oauth_passport_user_has_scope($scope)` - Check user scopes
* `oauth_passport_scopes` filter - Add custom scopes
* Complete REST API for client and token management

= Standards Compliance =

OAuth Passport follows these specifications:

* RFC 6749 (OAuth 2.0)
* RFC 7636 (PKCE)
* RFC 7591 (Dynamic Client Registration)
* RFC 7592 (Client Configuration)
* RFC 8414 (Authorization Server Metadata)
* OAuth 2.1 Draft Specification

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/oauth-passport` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. The plugin will automatically create the necessary database tables.
4. Use the Settings > OAuth Passport screen to configure the plugin.

= Manual Installation =

1. Download the plugin zip file
2. Extract and upload the `oauth-passport` folder to `/wp-content/plugins/`
3. Activate the plugin through WordPress admin
4. Configure settings in Settings > OAuth Passport

== Frequently Asked Questions ==

= What is OAuth 2.1? =

OAuth 2.1 is the latest version of the OAuth authorization framework. It consolidates security best practices and makes PKCE (Proof Key for Code Exchange) mandatory for all clients, providing enhanced security over OAuth 2.0.

= Do I need HTTPS? =

Yes, HTTPS is required in production environments for security. OAuth Passport will enforce this requirement unless you're in a development environment.

= Can I use this with mobile apps? =

Absolutely! OAuth Passport is perfect for mobile app authentication. It supports PKCE which is essential for mobile OAuth flows.

= How do I register OAuth clients? =

You can register clients in two ways:
1. Through the WordPress admin interface (Settings > OAuth Passport > OAuth Clients tab)
2. Via the REST API using dynamic client registration

= What databases are supported? =

OAuth Passport supports MySQL 5.7+, MariaDB 10.3+, and SQLite (via WordPress SQLite integration plugin).

= Can I customize the available scopes? =

Yes! Use the `oauth_passport_scopes` filter to add custom scopes for your specific use case.

== Screenshots ==

1. OAuth Passport Settings - Configure token lifetimes and view endpoints
2. OAuth Clients Management - Generate and manage OAuth clients
3. Active Tokens Monitoring - View and revoke active tokens
4. Authorization Consent Screen - User-friendly authorization interface

== Changelog ==

= 1.0.0 =
* Initial release
* OAuth 2.1 compliant authorization server
* Dynamic Client Registration (RFC 7591)
* Client Configuration Management (RFC 7592)
* Authorization Server Metadata discovery (RFC 8414)
* Protected Resource Metadata discovery (RFC 9728)
* JWKS endpoint for token validation
* PKCE mandatory support
* Authorization Code flow with refresh tokens
* Token rotation for security
* WordPress admin interface with React UI
* Comprehensive event logging
* Multi-database support (MySQL, MariaDB, SQLite)
* Helper functions for integration
* Rate limiting protection
* HTTPS enforcement
* Complete documentation

== Upgrade Notice ==

= 1.0.0 =
Initial release of OAuth Passport. Transform your WordPress site into a secure OAuth 2.1 authorization server.

== Technical Requirements ==

* WordPress 6.4 or higher
* PHP 8.0 or higher
* MySQL 5.7+ / MariaDB 10.3+ / SQLite
* HTTPS certificate (required in production)
* Pretty permalinks enabled

== Support ==

* Documentation: Comprehensive guides included with the plugin
* Issues: Report on GitHub repository
* Professional Support: Available for enterprise deployments

== Privacy ==

OAuth Passport stores OAuth tokens and client information in your WordPress database. No data is sent to external services. All token storage follows WordPress security best practices with proper hashing and encryption.

== Credits ==

OAuth Passport is built following OAuth 2.1 specifications and WordPress coding standards by Ovidiu Galatan.
