# OAuth Passport

A comprehensive OAuth 2.1 server for WordPress, enabling your site to act as an OAuth provider for third-party applications.

## Description

OAuth Passport transforms your WordPress site into a fully-featured OAuth 2.1 authorization server. It allows external applications to authenticate users and access your WordPress resources through secure, standards-compliant OAuth flows.

Whether you're building a mobile app, desktop application, or integrating with third-party services, OAuth Passport provides the authentication infrastructure you need.

## Features

- **OAuth 2.1 Compliant**: Full implementation with mandatory PKCE support
- **Dynamic Client Registration**: RFC 7591 compliant self-service client registration
- **Client Management**: RFC 7592 compliant configuration management
- **Secure Token Storage**: Database-backed tokens with automatic cleanup
- **Admin Interface**: Comprehensive WordPress admin panel for OAuth management
- **Flexible Scopes**: Fine-grained permission system
- **JWKS Support**: JSON Web Key Set endpoint for token validation
- **Discovery Endpoints**: OpenID Connect-style discovery for easy integration
- **WordPress Integration**: Works seamlessly with WordPress user system
- **REST API Compatible**: Protects any WordPress REST API endpoint
- **MCP Support**: Model Context Protocol server and client implementation for AI integration

## Use Cases

- **Mobile Apps**: Authenticate users in iOS/Android apps
- **Desktop Applications**: Secure authentication for desktop software
- **Third-party Integrations**: Allow external services to access your API
- **Single Sign-On (SSO)**: Use WordPress as the identity provider
- **API Access Control**: Manage who can access your REST APIs
- **Partner Integrations**: Provide secure access to business partners
- **Plugin Development**: Add OAuth support to your WordPress plugins
- **AI Integration**: Enable AI assistants to securely access WordPress data via MCP
- **Model Context Protocol**: Serve as an MCP server for AI model context management

## Installation

1. Upload the `OAuthPassport` folder to your `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. The plugin will automatically create the necessary database tables
4. Configure your OAuth settings in Settings > OAuth Passport

## Quick Start

### For Application Developers

1. **Register Your Application**

Send a POST request to register your application:

```bash
curl -X POST https://your-wordpress-site.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My Awesome App",
    "redirect_uris": ["https://myapp.com/callback"],
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "scope": "read write"
  }'
```

2. **Implement OAuth Flow**

Direct users to authorize your app:
```
https://your-wordpress-site.com/wp-json/oauth-passport/v1/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=YOUR_REDIRECT_URI&
  code_challenge=YOUR_CHALLENGE&
  code_challenge_method=S256&
  state=YOUR_STATE
```

3. **Exchange Code for Token**

After authorization, exchange the code for tokens:
```bash
curl -X POST https://your-wordpress-site.com/wp-json/oauth-passport/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=YOUR_VERIFIER"
```

### For WordPress Administrators

1. Navigate to **Settings > OAuth Passport** in your WordPress admin
2. Configure token lifetimes and security settings
3. View and manage registered OAuth clients
4. Monitor active tokens and revoke access when needed

## Integration Examples

### Protecting Custom Endpoints

```php
// In your plugin or theme
add_action('rest_api_init', function() {
    register_rest_route('myplugin/v1', '/data', [
        'methods' => 'GET',
        'callback' => 'my_protected_endpoint',
        'permission_callback' => 'is_user_logged_in', // OAuth Passport handles auth
    ]);
});

function my_protected_endpoint($request) {
    // This endpoint is now protected by OAuth
    return ['data' => 'secure information'];
}
```

### Checking OAuth Scopes

```php
// Get current OAuth token information
add_action('init', function() {
    if (function_exists('oauth_passport_get_current_token')) {
        $token = oauth_passport_get_current_token();
        if ($token && in_array('admin', explode(' ', $token->scope))) {
            // User has admin scope
        }
    }
});
```

### Adding Custom Scopes

```php
// Define custom scopes for your application
add_filter('oauth_passport_scopes', function($scopes) {
    $scopes['posts:publish'] = 'Publish posts';
    $scopes['media:upload'] = 'Upload media files';
    $scopes['comments:moderate'] = 'Moderate comments';
    return $scopes;
});
```

## Configuration

### Available Filters

- `oauth_passport_enabled` - Enable/disable OAuth functionality
- `oauth_passport_scopes` - Customize available scopes
- `oauth_passport_token_lifetime` - Adjust token expiration times
- `oauth_passport_is_development` - Control development mode features

### Settings

Configure through WordPress admin or programmatically:

```php
// Enable OAuth
add_filter('oauth_passport_enabled', '__return_true');

// Set custom token lifetime (in seconds)
add_filter('oauth_passport_access_token_lifetime', function() {
    return 7200; // 2 hours
});

// Allow localhost redirects in production
add_filter('oauth_passport_allow_localhost', '__return_true');
```

## API Endpoints

### OAuth Endpoints
- `POST /wp-json/oauth-passport/v1/register` - Dynamic client registration
- `GET/PUT/DELETE /wp-json/oauth-passport/v1/register/{client_id}` - Client management
- `GET/POST /wp-json/oauth-passport/v1/authorize` - Authorization endpoint
- `POST /wp-json/oauth-passport/v1/token` - Token endpoint
- `GET /wp-json/oauth-passport/v1/jwks` - JSON Web Key Set

### Discovery Endpoints
- `GET /.well-known/oauth-authorization-server` - OAuth 2.0 Authorization Server Metadata
- `GET /.well-known/oauth-protected-resource` - OAuth 2.0 Protected Resource Metadata

## Security

OAuth Passport implements industry-standard security measures:

- **PKCE Required**: Protects against authorization code interception
- **Token Rotation**: Refresh tokens are rotated on use
- **Secure Storage**: All secrets are properly hashed
- **HTTPS Enforcement**: Required in production environments
- **Rate Limiting**: Protects against brute force attacks
- **Event Logging**: Comprehensive audit trail

## Compatibility

- WordPress 6.4 or higher
- PHP 8.0 or higher
- MySQL 5.7+ or MariaDB 10.3+
- HTTPS required in production

## Support

- **Documentation**: See `/includes/Auth/README.md` for detailed documentation
- **Troubleshooting**: Check `/includes/Auth/TROUBLESHOOTING.md` for common issues
- **Issues**: Report bugs on our GitHub repository
- **Professional Support**: Available for enterprise deployments

## License

GPL-2.0-or-later

## Credits

OAuth Passport is built following OAuth 2.1 specifications and best practices from:
- RFC 6749 (OAuth 2.0)
- RFC 7636 (PKCE)
- RFC 7591 (Dynamic Client Registration)
- RFC 7592 (Client Configuration)
- RFC 8414 (Authorization Server Metadata)
- OAuth 2.1 Draft Specification 