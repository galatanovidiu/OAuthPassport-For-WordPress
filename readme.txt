=== OAuth Passport ===
Contributors: galatanovidiu
Tags: oauth, oauth2, authentication, api, rest-api, security, authorization, token, pkce
Requires at least: 6.4
Tested up to: 6.7
Requires PHP: 8.0
Stable tag: 0.0.1
License: MIT
License URI: https://opensource.org/licenses/MIT

⚠️ EXPERIMENTAL ALPHA - For testing only. NOT for production use.

Transform your WordPress site into a secure OAuth 2.1 authorization server. Enable third-party applications to authenticate users and access your APIs.

== Description ==

**⚠️ IMPORTANT: This is an EXPERIMENTAL ALPHA release intended for testing and development only. DO NOT use in production environments. APIs and features may change significantly.**

OAuth Passport transforms your WordPress site into a **secure OAuth 2.1 authorization server**. It enables external applications to authenticate users and access your WordPress resources through standards-compliant OAuth flows.

**MCP Compliant**: Fully compliant with the [Model Context Protocol (MCP) Authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization), making it the ideal authorization server for MCP implementations.

Perfect for developers building MCP servers, mobile apps, desktop applications, or integrating with third-party services.

= Alpha Release Limitations =

* Limited production testing
* APIs may change between versions
* Breaking changes possible
* Use for development/testing only
* No upgrade path guaranteed

= Key Features =

* **MCP Authorization Compliant** - Fully compliant with Model Context Protocol requirements
* **OAuth 2.1 Compliant** - Full implementation with mandatory PKCE support
* **Dynamic Client Registration** - Self-service client registration (RFC 7591)
* **Protected Resource Metadata** - RFC 9728 support for authorization server discovery
* **Resource Indicators** - RFC 8707 support for token audience binding
* **React Admin Interface** - Modern admin panel for managing clients and tokens
* **Discovery Endpoints** - Automatic configuration discovery for easy integration
* **WordPress Integration** - Seamless integration with WordPress user system
* **Secure by Default** - HTTPS enforcement, token rotation, and rate limiting

= Use Cases =

* **MCP Servers** - Authorization server for Model Context Protocol implementations
* **Mobile Apps** - Authenticate users in iOS/Android applications
* **Desktop Applications** - Secure authentication for desktop software
* **Third-party Integrations** - Allow external services to access your APIs
* **Single Sign-On (SSO)** - Use WordPress as the identity provider
* **API Access Control** - Manage who can access your REST APIs
* **Plugin Development** - Add OAuth support to your WordPress plugins

= Security Features =

* **PKCE Required** - All authorization flows require PKCE for security
* **Token Rotation** - Refresh tokens rotate on each use
* **Secure Storage** - All secrets are properly hashed and encrypted
* **HTTPS Enforcement** - Required in production environments
* **Rate Limiting** - Protects against brute force attacks

= Developer Friendly =

OAuth Passport provides helper functions for easy integration:

* `oauth_passport_get_current_token()` - Get current OAuth token
* `oauth_passport_user_has_scope($scope)` - Check user permissions
* `oauth_passport_user_can($scope)` - Unified permission checking
* Complete REST API for client and token management

= Standards Compliance =

OAuth Passport is fully compliant with the [Model Context Protocol (MCP) Authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) and implements:

* Model Context Protocol Authorization Requirements
* OAuth 2.1 specification (draft-ietf-oauth-v2-1-13)
* RFC 7591 - Dynamic Client Registration Protocol
* RFC 7636 - Proof Key for Code Exchange (PKCE - Mandatory)
* RFC 8414 - Authorization Server Metadata
* RFC 9728 - Protected Resource Metadata
* RFC 8707 - Resource Indicators for OAuth 2.0
* RFC 6750 - Bearer Token Usage

== Installation ==

**Note: This is an alpha release. Install only in development/testing environments.**

1. Upload the plugin files to `/wp-content/plugins/oauth-passport/` or install through WordPress admin
2. Activate the plugin through the 'Plugins' screen
3. Navigate to **Settings > OAuth Passport** to configure
4. If rewrite rules don't work, go to Settings > Permalinks and click Save
4. Register your first OAuth client to get started

= Manual Installation =

1. Download the plugin zip file
2. Extract and upload the `oauth-passport` folder to `/wp-content/plugins/`
3. Activate through WordPress admin
4. Configure in **Settings > OAuth Passport**

== Frequently Asked Questions ==

= What is OAuth 2.1? =

OAuth 2.1 is the latest version of the OAuth authorization framework. It consolidates security best practices and makes PKCE mandatory for all clients, providing enhanced security over OAuth 2.0.

= Do I need HTTPS? =

Yes, HTTPS is required in production environments for security. OAuth Passport enforces this requirement unless you're in a development environment.

= Can I use this with mobile apps? =

Absolutely! OAuth Passport is perfect for mobile app authentication. It supports PKCE which is essential for secure mobile OAuth flows.

= How do I register OAuth clients? =

You can register clients in two ways:
1. Through the WordPress admin interface (**Settings > OAuth Passport > OAuth Clients**)
2. Via the REST API using dynamic client registration

= What databases are supported? =

OAuth Passport supports MySQL 5.7+, MariaDB 10.3+, and SQLite (with WordPress SQLite integration plugin).

= Can I customize the available scopes? =

Yes! Use the `oauth_passport_scopes` filter to add custom scopes:

`add_filter('oauth_passport_scopes', function($scopes) {
    $scopes['custom'] = 'Custom permission description';
    return $scopes;
});`

== Screenshots ==

1. **OAuth Settings** - Configure token lifetimes and security settings
2. **Client Management** - Register and manage OAuth client applications
3. **Token Monitoring** - View and revoke active OAuth tokens
4. **Authorization Screen** - User-friendly consent interface

== Changelog ==

= 0.0.1 =
* Initial alpha release
* Model Context Protocol (MCP) Authorization compliant
* OAuth 2.1 compliant authorization server
* Dynamic Client Registration (RFC 7591)
* Protected Resource Metadata (RFC 9728)
* Authorization Server Metadata discovery (RFC 8414)
* Resource Indicators support (RFC 8707)
* JWKS endpoint for token validation
* PKCE mandatory support for all flows
* Authorization Code flow with refresh tokens
* Token rotation and audience validation
* React-based admin interface
* Comprehensive security features
* WordPress integration with user system
* Helper functions for developers
* Complete documentation and examples

== Upgrade Notice ==

= 0.0.1 =
⚠️ EXPERIMENTAL ALPHA RELEASE - For testing and development only. DO NOT use in production. Initial alpha release of OAuth Passport. Transform your WordPress site into a secure OAuth 2.1 authorization server.

== Technical Requirements ==

* WordPress 6.4 or higher
* PHP 8.0 or higher
* MySQL 5.7+ / MariaDB 10.3+ / SQLite
* HTTPS certificate (required in production)
* Pretty permalinks enabled
* Modern browser for admin interface

== API Endpoints ==

OAuth Passport provides these REST API endpoints:

**OAuth Endpoints:**
* `POST /wp-json/oauth-passport/v1/register` - Register new client
* `GET/POST /wp-json/oauth-passport/v1/authorize` - Authorization endpoint
* `POST /wp-json/oauth-passport/v1/token` - Token endpoint
* `GET /wp-json/oauth-passport/v1/jwks` - JSON Web Key Set

**Discovery:**
* `GET /.well-known/oauth-authorization-server` - Server metadata
* `GET /.well-known/oauth-protected-resource` - Resource metadata

**Admin API:**
* `GET /wp-json/oauth-passport/v1/admin/clients` - List registered clients
* `GET /wp-json/oauth-passport/v1/admin/tokens` - List active tokens

== Privacy ==

OAuth Passport stores OAuth tokens and client information in your WordPress database. No data is sent to external services. All token storage follows WordPress security best practices with proper hashing and encryption.

The plugin does not collect any personal data beyond what is necessary for OAuth functionality (user ID, client information, and token metadata).

== Support ==

* **Documentation**: See [docs/](https://github.com/galatanovidiu/oauth-passport/tree/main/docs) folder for comprehensive guides
* **GitHub**: Report issues and contribute on [GitHub](https://github.com/galatanovidiu/oauth-passport/issues)

== Credits ==

OAuth Passport is built following OAuth 2.1 specifications and WordPress coding standards by Ovidiu Galatan.

Special thanks to the OAuth working group and WordPress community for their excellent specifications and tools.