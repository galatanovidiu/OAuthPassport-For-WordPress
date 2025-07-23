# OAuth 2.1 Server for WordPress

This is a comprehensive OAuth 2.1 server implementation for WordPress, providing secure token-based authentication for any WordPress application or API.

## Overview

OAuth Passport is a standalone OAuth 2.1 server that enables WordPress sites to act as OAuth providers. It allows third-party applications to authenticate users and access WordPress resources through standardized OAuth flows.

## Features

### Core OAuth Features ✅
- **OAuth 2.1 compliant** with mandatory PKCE (S256 only)
- **Authorization Code flow** with refresh tokens
- **Dynamic Client Registration** (RFC 7591)
- **OAuth Server Metadata Discovery** (RFC 8414)
- **Protected Resource Metadata Discovery** (RFC 9728)
- **JSON Web Key Set (JWKS)** endpoint for key discovery
- **Refresh Token Support** with token rotation
- **Scope Management** with customizable permissions
- **WordPress Admin Interface** for OAuth management
- **Enhanced Error Logging** and monitoring
- **Configurable token expiration** (default: 1 hour access, 30 days refresh)
- **Two database tables** for scalability
- **Integration with WordPress authentication system**

## Discovery Endpoints

The implementation provides standard OAuth discovery endpoints for automatic client configuration:

### OAuth Authorization Server Metadata (RFC 8414)
`GET /.well-known/oauth-authorization-server`

**Response:**
```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/wp-json/oauth-passport/v1/authorize",
  "token_endpoint": "https://example.com/wp-json/oauth-passport/v1/token",
  "registration_endpoint": "https://example.com/wp-json/oauth-passport/v1/register",
  "jwks_uri": "https://example.com/wp-json/oauth-passport/v1/jwks",
  "scopes_supported": ["read", "write", "admin", "user:read", "user:write"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "code_challenge_methods_supported": ["S256"]
}
```

### Protected Resource Metadata (RFC 9728)
`GET /.well-known/oauth-protected-resource`

**Response:**
```json
{
  "resource": "https://example.com",
  "authorization_servers": ["https://example.com"],
  "scopes_supported": ["read", "write", "admin", "user:read", "user:write"],
  "bearer_methods_supported": ["header"],
  "jwks_uri": "https://example.com/wp-json/oauth-passport/v1/jwks"
}
```

## Dynamic Client Registration

The implementation supports dynamic client registration as per RFC 7591. This allows OAuth clients to self-register without manual configuration.

### Registration Endpoint

`POST /wp-json/oauth-passport/v1/register`

**Request Body:**
```json
{
  "client_name": "My Application",
  "redirect_uris": [
    "http://localhost:8080/callback",
    "https://my-app.com/callback"
  ],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "read write",
  "contacts": ["admin@example.com"],
  "logo_uri": "https://example.com/logo.png",
  "client_uri": "https://example.com",
  "policy_uri": "https://example.com/privacy",
  "tos_uri": "https://example.com/terms"
}
```

**Response:**
```json
{
  "client_id": "oauth_xxxxxxxxxxxxxxxx",
  "client_secret": "xxxxxxxxxxxxxxxx",
  "client_id_issued_at": 1704127200,
  "client_secret_expires_at": 0,
  "registration_access_token": "registration_xxxxxxxxxx",
  "registration_client_uri": "https://example.com/wp-json/oauth-passport/v1/register/oauth_xxxxxxxx",
  "client_name": "My Application",
  "redirect_uris": ["http://localhost:8080/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "read write",
  "token_endpoint_auth_method": "client_secret_post"
}
```

### Client Configuration Management

After registration, clients can manage their configuration using the registration access token:

#### Get Client Configuration
```bash
GET /wp-json/oauth-passport/v1/register/{client_id}
Authorization: Bearer {registration_access_token}
```

#### Update Client Configuration
```bash
PUT /wp-json/oauth-passport/v1/register/{client_id}
Authorization: Bearer {registration_access_token}
Content-Type: application/json

{
  "client_name": "Updated Client Name",
  "redirect_uris": ["https://new-callback.com/oauth"]
}
```

#### Delete Client
```bash
DELETE /wp-json/oauth-passport/v1/register/{client_id}
Authorization: Bearer {registration_access_token}
```

## OAuth Flow

### Step 1: Authorization Request

Direct the user to:
```
GET /wp-json/oauth-passport/v1/authorize?
  client_id={client_id}
  &redirect_uri={redirect_uri}
  &code_challenge={code_challenge}
  &code_challenge_method=S256
  &state={state}
```

### Step 2: User Authorization

User logs in (if needed) and authorizes the application. They are redirected to:
```
{redirect_uri}?code={auth_code}&state={state}
```

### Step 3: Token Exchange

Exchange the authorization code for an access token:
```
POST /wp-json/oauth-passport/v1/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "code": "{auth_code}",
  "client_id": "{client_id}",
  "client_secret": "{client_secret}",
  "code_verifier": "{code_verifier}"
}
```

Response:
```json
{
  "access_token": "access_xxxxxxxxxxxxx",
  "refresh_token": "refresh_xxxxxxxxxxxxx",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

### Step 4: Token Refresh

When the access token expires, use the refresh token to get a new one:
```
POST /wp-json/oauth-passport/v1/token
Content-Type: application/json

{
  "grant_type": "refresh_token",
  "refresh_token": "{refresh_token}",
  "client_id": "{client_id}",
  "client_secret": "{client_secret}"
}
```

Response:
```json
{
  "access_token": "access_new_xxxxxxxxxxxxx",
  "refresh_token": "refresh_new_xxxxxxxxxxxxx",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

### Step 5: API Access

Use the access token for API requests:
```
GET /wp-json/wp/v2/posts
Authorization: Bearer {access_token}
```

## JWKS Endpoint

The JWKS endpoint provides public key discovery for JWT signature verification:

`GET /wp-json/oauth-passport/v1/jwks`

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-xxxxxxxxxxxxxxxx",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

## OAuth Scopes

The implementation supports the following default scopes:

- **read** - Read access to WordPress resources
- **write** - Write access to WordPress resources
- **admin** - Administrative access
- **user:read** - Read user information
- **user:write** - Modify user information

Custom scopes can be added through WordPress filters:

```php
add_filter('oauth_passport_scopes', function($scopes) {
    $scopes['custom:scope'] = 'Description of custom scope';
    return $scopes;
});
```

## WordPress Admin Interface

OAuth management is available in the WordPress admin under **Settings > OAuth Passport**:

### Features:
- **OAuth Settings** - Enable/disable OAuth, configure token lifetimes
- **Client Management** - View, create, and revoke OAuth clients
- **Token Management** - View active tokens and revoke them
- **Error Logs** - Monitor OAuth events and errors

### Admin Pages:
1. **Settings Page** (`/wp-admin/options-general.php?page=oauth-passport`)
   - Enable/disable OAuth
   - Configure access token lifetime (default: 1 hour)
   - Configure refresh token lifetime (default: 30 days)
   - View all OAuth endpoints

2. **Clients Page** (`/wp-admin/admin.php?page=oauth-passport-clients`)
   - List all registered clients
   - Generate manual clients
   - Revoke client access

3. **Tokens Page** (`/wp-admin/admin.php?page=oauth-passport-tokens`)
   - View active access and refresh tokens
   - See token metadata (client, user, scopes, expiration)
   - Revoke individual tokens

## Integration with Other Plugins

OAuth Passport can be integrated with any WordPress plugin or theme. Here's how to protect your custom endpoints:

```php
// In your plugin or theme
add_filter('rest_authentication_errors', function($result) {
    // OAuth Passport will handle authentication
    return $result;
});

// Check if user is authenticated via OAuth
if (is_user_logged_in()) {
    // User authenticated via OAuth or WordPress session
}

// Get OAuth token information
add_action('rest_api_init', function() {
    $token = oauth_passport_get_current_token();
    if ($token) {
        $scopes = $token->scope;
        $client_id = $token->client_id;
        // Use token information
    }
});
```

## Manual Client Configuration

For clients that don't support dynamic registration, you can manually configure them:

```php
// In your WordPress site
add_action('init', function() {
    $clients = get_option('oauth_passport_clients', array());
    
    $clients['manual_client_id'] = array(
        'client_secret' => 'your_secret_here',
        'redirect_uri'  => 'https://your-app.com/callback',
    );
    
    update_option('oauth_passport_clients', $clients);
});
```

## Security Considerations

1. **PKCE is mandatory** - All authorization requests must include code_challenge
2. **HTTPS required in production** - Use secure connections
3. **Token rotation** - New refresh tokens issued on each refresh
4. **Configurable expiration** - Customize token lifetimes per deployment
5. **Registration tokens** - Keep registration access tokens secure
6. **Localhost URLs** - Allowed only in development environments (WP_DEBUG=true or WP_ENVIRONMENT_TYPE=local/development)
7. **Audience restriction** - Tokens are bound to specific resources
8. **Scope enforcement** - Fine-grained permission control
9. **Event logging** - All OAuth events are logged for security monitoring
10. **Rate limiting** - Protection against brute force attacks (configurable)

## Database Schema

Three tables are created for OAuth functionality:

### wp_oauth_passport_tokens
- Stores authorization codes, access tokens, refresh tokens, and registration tokens
- Supports token rotation and scope storage
- Automatic cleanup of expired tokens
- Indexes for performance optimization

### wp_oauth_passport_clients
- Stores dynamically registered client information
- Includes all RFC 7591 metadata fields
- Supports client configuration management

### wp_oauth_passport_logs
- Event logging for security monitoring
- Tracks authorization attempts, token generation, and errors
- Configurable retention period (default: 30 days)
- Used for debugging and security auditing

## Error Responses

All OAuth errors follow RFC 6749 format:

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

## File Structure

```
includes/Auth/
├── OAuth2Server.php     # Main OAuth server implementation
├── Schema.php           # Database schema management
├── PKCEValidator.php    # PKCE validation
├── DiscoveryServer.php  # OAuth discovery endpoints (RFC 8414, RFC 9728)
├── JWKSServer.php       # JSON Web Key Set endpoint
├── ScopeManager.php     # OAuth scope validation and enforcement
├── AdminInterface.php   # WordPress admin interface
├── ErrorLogger.php      # Enhanced error logging
├── TokenGenerator.php   # Token generation utilities
├── README.md            # This documentation
└── TROUBLESHOOTING.md   # Common issues and solutions
```

## Token Management

### Access Tokens
- **Default expiration**: 1 hour (configurable in admin)
- **Usage**: API access with Bearer authorization
- **Refresh**: Use refresh token when expired

### Refresh Tokens
- **Default expiration**: 30 days (configurable in admin)
- **Usage**: Obtain new access tokens
- **Security**: Bound to specific client and user
- **Rotation**: New refresh token issued on each use

### Token Cleanup
- Expired tokens are automatically cleaned up daily
- Manual cleanup available in admin interface

## Standard Compliance

This implementation follows these OAuth specifications:

1. **RFC 6749** - OAuth 2.0 Authorization Framework
2. **RFC 7636** - PKCE (Proof Key for Code Exchange)
3. **RFC 7591** - Dynamic Client Registration ✅
4. **RFC 7592** - Client Configuration Management ✅
5. **RFC 8414** - Authorization Server Metadata ✅
6. **RFC 9728** - Protected Resource Metadata ✅
7. **OAuth 2.1** - Latest security best practices

## Testing

### Dynamic Client Registration Test
```bash
# Register a test client
curl -X POST http://your-site.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

### Discovery Endpoints Test
```bash
# Get authorization server metadata
curl http://your-site.com/.well-known/oauth-authorization-server

# Get protected resource metadata
curl http://your-site.com/.well-known/oauth-protected-resource
```

### OAuth Flow Test
1. **Authorization**: Visit the authorize URL with proper parameters
2. **Token Exchange**: POST to token endpoint with authorization code
3. **API Access**: Use Bearer token to access protected resources
4. **Token Refresh**: Use refresh token to get new access tokens

## Troubleshooting

### "Invalid client" Error
- Verify client_id matches exactly
- Check client_secret for confidential clients
- Ensure client is registered (check `wp_oauth_passport_clients` table)
- For dynamic clients, verify registration was successful

### "Invalid grant" Error
- Authorization code may have expired (5 minutes)
- PKCE verifier doesn't match challenge
- Code was already used (codes are one-time use)
- Check redirect_uri matches exactly
- For refresh tokens, ensure token hasn't expired or been revoked

### Token Not Working
- Token may have expired (check `expires_in`)
- Ensure Authorization header format: `Authorization: Bearer TOKEN`
- Verify token exists in `wp_oauth_passport_tokens` table
- Check if OAuth is enabled in WordPress admin
- Verify token has required scopes

### Discovery Not Working
- Ensure pretty permalinks are enabled
- Check `.htaccess` file permissions
- Verify WordPress REST API is working: `/wp-json/`
- Test with: `curl http://your-site/.well-known/oauth-authorization-server`
- Check for plugin conflicts

### Admin Interface Issues
- Verify user has `manage_options` capability
- Check browser console for JavaScript errors
- Ensure database tables were created properly
- Clear browser cache and WordPress cache

### Scope Errors
- Verify requested scopes are supported
- Check user has capabilities for requested scopes
- Ensure token was granted the required scopes
- Review scope configuration in admin

### Database Issues
- Run database upgrade: visit OAuth admin page
- Check table creation permissions
- Verify table prefix matches WordPress configuration
- Check for MySQL/MariaDB version compatibility

For more detailed troubleshooting, check the OAuth event logs in the WordPress admin or see `TROUBLESHOOTING.md`. 