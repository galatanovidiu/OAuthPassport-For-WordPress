# OAuth Passport

Transform your WordPress site into a secure OAuth 2.1 authorization server. Enable third-party applications to authenticate users and access your APIs through standards-compliant OAuth flows.

## Features

- **OAuth 2.1 Compliant** - Full implementation with mandatory PKCE support
- **Dynamic Client Registration** - Self-service client registration (RFC 7591)
- **WordPress Integration** - Seamless integration with WordPress user system
- **Admin Interface** - React-based admin panel for managing clients and tokens
- **Discovery Endpoints** - Automatic configuration discovery for easy integration
- **Secure by Default** - HTTPS enforcement, token rotation, and rate limiting

## Installation

1. Upload the plugin to `/wp-content/plugins/oauth-passport`
2. Activate through WordPress admin
3. Configure settings in **Settings > OAuth Passport**

## Quick Start

### 1. Register a Client Application

**Via Admin Panel:**
Go to Settings > OAuth Passport > OAuth Clients

**Via API:**
```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://myapp.com/callback"]
  }'
```

### 2. Implement OAuth Flow

**Authorization URL:**
```
https://yoursite.com/wp-json/oauth-passport/v1/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=YOUR_REDIRECT_URI&
  code_challenge=YOUR_PKCE_CHALLENGE&
  code_challenge_method=S256&
  response_type=code&
  scope=read
```

**Token Exchange:**
```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "code_verifier=YOUR_PKCE_VERIFIER"
```

## API Endpoints

### OAuth Endpoints
- `POST /wp-json/oauth-passport/v1/register` - Register new client
- `GET|PUT|DELETE /wp-json/oauth-passport/v1/register/{client_id}` - Manage client registration
- `GET/POST /wp-json/oauth-passport/v1/authorize` - Authorization endpoint
- `POST /wp-json/oauth-passport/v1/token` - Token endpoint

### Discovery
- `GET /.well-known/oauth-authorization-server` - Server metadata (RFC 8414)
- `GET /.well-known/oauth-protected-resource` - Resource metadata (RFC 9728)

### Admin API
- `GET /wp-json/oauth-passport/v1/admin/clients` - List clients
- `DELETE /wp-json/oauth-passport/v1/admin/clients/{client_id}` - Delete client
- `DELETE /wp-json/oauth-passport/v1/admin/clients/{client_id}/tokens` - Revoke client tokens
- `GET /wp-json/oauth-passport/v1/admin/tokens` - List active tokens
- `DELETE /wp-json/oauth-passport/v1/admin/tokens/{token_id}` - Revoke token
- `POST /wp-json/oauth-passport/v1/admin/tokens/generate` - Generate tokens (admin)
- `GET /wp-json/oauth-passport/v1/admin/endpoints` - List all endpoints

## OAuth Scopes

- **read** - Access to read content and user profile
- **write** - Create and edit posts, pages, and media
- **admin** - Manage site settings and users

Add custom scopes using the `oauth_passport_scopes` filter.

## Developer Integration

### Access Plugin Services

```php
// Get the plugin runtime
$runtime = \OAuthPassport\oauth_passport_runtime();

// Access scope manager
$scope_manager = $runtime->scopeManager();
$scopes = $scope_manager->getAvailableScopes();

// Access token service
$token_service = $runtime->tokenService();

// Access client service
$client_service = $runtime->clientService();
```

### Add Custom Scopes
```php
add_filter('oauth_passport_scopes', function($scopes) {
    $scopes['custom'] = 'Custom permission';
    return $scopes;
});
```

### Protect Custom REST Endpoints

Use WordPress's built-in authentication which OAuth Passport extends:

```php
add_action('rest_api_init', function() {
    register_rest_route('myapp/v1', '/data', [
        'methods' => 'GET',
        'callback' => 'my_endpoint_callback',
        'permission_callback' => function() {
            // WordPress handles OAuth token authentication automatically
            return current_user_can('read');
        }
    ]);
});
```

## Configuration

### Settings
Configure through WordPress admin or filters:

```php
// Enable/disable OAuth
add_filter('oauth_passport_enabled', '__return_true');

// Set token lifetime (seconds)
add_filter('oauth_passport_access_token_lifetime', function() {
    return 3600; // 1 hour
});

// Allow localhost redirects (development only)
add_filter('oauth_passport_allow_localhost', '__return_true');
```

### Available Filters
- `oauth_passport_enabled` - Enable/disable functionality
- `oauth_passport_scopes` - Add custom scopes
- `oauth_passport_access_token_lifetime` - Token expiration
- `oauth_passport_refresh_token_lifetime` - Refresh token expiration
- `oauth_passport_allow_localhost` - Allow localhost redirects

## Requirements

- WordPress 6.4+
- PHP 8.1+
- MySQL 5.7+ / MariaDB 10.3+
- HTTPS (required in production)
- Pretty permalinks enabled
- OpenSSL PHP extension

## Security

OAuth Passport follows security best practices:

- **PKCE Required** - All authorization flows require PKCE
- **Token Rotation** - Refresh tokens rotate on each use
- **Secure Storage** - All secrets are properly hashed
- **HTTPS Enforcement** - Required in production
- **Rate Limiting** - Protects against brute force attacks

## Standards Compliance

- RFC 6749 (OAuth 2.0)
- RFC 7636 (PKCE - Mandatory)
- RFC 7591 (Dynamic Client Registration)
- RFC 7592 (Dynamic Client Management)
- RFC 8414 (Authorization Server Metadata)
- RFC 8707 (Resource Indicators)
- RFC 9728 (Protected Resource Metadata)
- OAuth 2.1 Draft Specification
- MCP (Model Context Protocol) Authorization Support

## License

MIT License - see LICENSE file for details.