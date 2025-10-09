# OAuth 2.1 Server Documentation

This documentation covers the core OAuth 2.1 server implementation for WordPress.

## Overview

OAuth Passport transforms your WordPress site into a secure OAuth 2.1 authorization server, allowing third-party applications to authenticate users and access WordPress resources.

## Quick Start

### 1. Client Registration

Register a new OAuth client via API:

```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://myapp.com/callback"]
  }'
```

Response includes `client_id`, `client_secret`, and `registration_access_token`.

### 2. Authorization Flow

1. **Authorization Request:**
```
https://yoursite.com/wp-json/oauth-passport/v1/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=YOUR_REDIRECT_URI&
  code_challenge=YOUR_PKCE_CHALLENGE&
  code_challenge_method=S256&
  response_type=code&
  scope=read
```

2. **Token Exchange:**
```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=YOUR_PKCE_VERIFIER"
```

3. **API Access:**
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  https://yoursite.com/wp-json/wp/v2/posts
```

## API Endpoints

### OAuth Endpoints
- `POST /wp-json/oauth-passport/v1/register` - Client registration (RFC 7591)
- `GET /wp-json/oauth-passport/v1/register/{client_id}` - Get client configuration
- `PUT /wp-json/oauth-passport/v1/register/{client_id}` - Update client configuration
- `DELETE /wp-json/oauth-passport/v1/register/{client_id}` - Delete client
- `GET/POST /wp-json/oauth-passport/v1/authorize` - Authorization endpoint
- `POST /wp-json/oauth-passport/v1/token` - Token exchange/refresh

### Discovery Endpoints
- `GET /.well-known/oauth-authorization-server` - Server metadata (RFC 8414)
- `GET /.well-known/oauth-protected-resource` - Resource metadata (RFC 9728)

### Admin Endpoints
- `GET /wp-json/oauth-passport/v1/admin/clients` - List all clients
- `DELETE /wp-json/oauth-passport/v1/admin/clients/{client_id}` - Delete client
- `DELETE /wp-json/oauth-passport/v1/admin/clients/{client_id}/tokens` - Revoke all client tokens
- `GET /wp-json/oauth-passport/v1/admin/tokens` - List active tokens
- `DELETE /wp-json/oauth-passport/v1/admin/tokens/{token_id}` - Revoke specific token
- `POST /wp-json/oauth-passport/v1/admin/tokens/generate` - Generate tokens (admin only)
- `GET /wp-json/oauth-passport/v1/admin/endpoints` - List all available endpoints

## OAuth Scopes

Default scopes:
- **read** - Access to read content and user profile
- **write** - Create and edit posts, pages, and media
- **admin** - Manage site settings and users

Add custom scopes:
```php
add_filter('oauth_passport_scopes', function($scopes) {
    $scopes['custom'] = 'Custom permission';
    return $scopes;
});
```

## Client Management

### Dynamic Registration (RFC 7591)

After registration, manage clients with the registration access token:

**Get client info:**
```bash
GET /wp-json/oauth-passport/v1/register/{client_id}
Authorization: Bearer {registration_access_token}
```

**Update client:**
```bash
PUT /wp-json/oauth-passport/v1/register/{client_id}
Authorization: Bearer {registration_access_token}
Content-Type: application/json

{
  "client_name": "Updated Name",
  "redirect_uris": ["https://new-callback.com"]
}
```

**Delete client:**
```bash
DELETE /wp-json/oauth-passport/v1/register/{client_id}
Authorization: Bearer {registration_access_token}
```

## WordPress Integration

### Admin Interface

Access OAuth management at **Settings > OAuth Passport**:
- View and manage registered clients
- Monitor active tokens and revoke access
- Generate tokens for testing
- View endpoint information

### Runtime Access

Access plugin services through the runtime:

```php
// Get the runtime instance
$runtime = \OAuthPassport\oauth_passport_runtime();

// Access services
$scope_manager = $runtime->scopeManager();
$token_service = $runtime->tokenService();
$client_service = $runtime->clientService();
$token_repository = $runtime->tokenRepository();
$client_repository = $runtime->clientRepository();

// Example: Validate scopes
$valid_scopes = $scope_manager->validate(['read', 'write']);

// Example: Check user can access scope
$can_access = $scope_manager->userCanAccessScope($user_id, 'admin');
```

### WP-CLI Commands

Generate tokens from command line:

```bash
wp oauth-passport generate-tokens <user_id> \
  --client_id=<client_id> \
  --scope="read write"
```

### Protect Custom Endpoints

OAuth Passport integrates with WordPress's REST API authentication:

```php
add_action('rest_api_init', function() {
    register_rest_route('myapp/v1', '/data', [
        'methods' => 'GET',
        'callback' => 'my_endpoint_callback',
        'permission_callback' => function() {
            // WordPress automatically authenticates OAuth tokens
            // Just use standard WordPress capability checks
            return current_user_can('read');
        }
    ]);
});
```

## Configuration

### Settings Filters

```php
// Enable/disable OAuth
add_filter('oauth_passport_enabled', '__return_true');

// Token lifetime (seconds)
add_filter('oauth_passport_access_token_lifetime', function() {
    return 3600; // 1 hour
});

add_filter('oauth_passport_refresh_token_lifetime', function() {
    return 2592000; // 30 days
});

// Allow localhost redirects (development only)
add_filter('oauth_passport_allow_localhost', '__return_true');
```

### Available Filters
- `oauth_passport_enabled` - Enable/disable functionality
- `oauth_passport_scopes` - Add custom scopes
- `oauth_passport_access_token_lifetime` - Access token expiration
- `oauth_passport_refresh_token_lifetime` - Refresh token expiration
- `oauth_passport_allow_localhost` - Allow localhost redirects

## Database Schema

### Tables Created
- `wp_oauth_passport_tokens` - Stores all token types (access, refresh, authorization codes)
- `wp_oauth_passport_clients` - Registered OAuth clients

### Token Types
- `code` - Authorization codes (5 minutes expiration)
- `access` - Access tokens (1 hour default, configurable)
- `refresh` - Refresh tokens (30 days default, configurable)
- `registration` - Registration access tokens (never expire)

### Key Features
- **Opaque tokens** - Random strings stored in database (not JWT)
- **Resource indicators** - Support for RFC 8707 resource parameter
- **Token versioning** - Schema version tracking for migrations
- **Automatic cleanup** - Expired tokens can be cleaned via cron

## Security Features

- **PKCE Required** - All authorization flows require PKCE with S256
- **Token Rotation** - Refresh tokens rotate on each use
- **Secure Storage** - All secrets are properly hashed
- **HTTPS Enforcement** - Required in production
- **Rate Limiting** - Protection against brute force attacks
- **Event Logging** - Comprehensive audit trail

## Standards Compliance

- **RFC 6749** - OAuth 2.0 Authorization Framework
- **RFC 7636** - PKCE (Proof Key for Code Exchange) - **Mandatory**
- **RFC 7591** - Dynamic Client Registration Protocol
- **RFC 7592** - Dynamic Client Management Protocol
- **RFC 8414** - Authorization Server Metadata
- **RFC 8707** - Resource Indicators for OAuth 2.0
- **RFC 9728** - OAuth 2.0 Protected Resource Metadata
- **OAuth 2.1** - Draft Specification (consolidated best practices)
- **MCP** - Model Context Protocol Authorization Support

### OAuth 2.1 Compliance

OAuth Passport follows OAuth 2.1 requirements:
- ✅ PKCE mandatory for all authorization code flows
- ✅ No implicit grant (removed in 2.1)
- ✅ No resource owner password credentials grant
- ✅ Refresh token rotation supported
- ✅ Redirect URI exact matching

## Resource Indicators (RFC 8707)

OAuth Passport supports RFC 8707 Resource Indicators, allowing clients to specify which resource server they want to access with the token.

### How It Works

Clients can include a `resource` parameter in authorization and token requests:

```bash
# Authorization request with resource
GET /oauth-passport/v1/authorize?
  client_id=CLIENT_ID&
  redirect_uri=REDIRECT_URI&
  response_type=code&
  code_challenge=CHALLENGE&
  code_challenge_method=S256&
  resource=https://api.example.com
```

```bash
# Token request with resource
POST /oauth-passport/v1/token
  grant_type=authorization_code&
  code=AUTH_CODE&
  client_id=CLIENT_ID&
  client_secret=CLIENT_SECRET&
  code_verifier=VERIFIER&
  resource=https://api.example.com
```

### Benefits

- **Token scoping** - Tokens are bound to specific resource servers
- **Security** - Prevents token misuse across different services
- **MCP support** - Required for Model Context Protocol authorization
- **Multi-service** - Support multiple resource servers with different tokens

### Client Configuration

Clients can register allowed resources during registration:

```json
{
  "client_name": "My App",
  "redirect_uris": ["https://app.example.com/callback"],
  "allowed_resources": [
    "https://api.example.com",
    "https://mcp.example.com/server"
  ]
}
```

When `allowed_resources` is configured, the authorization server will validate that requested resources are in the allowed list.

## Plugin Architecture

### Runtime Container

OAuth Passport uses a lightweight Runtime container for dependency management:

```php
// Access the runtime
$runtime = \OAuthPassport\oauth_passport_runtime();

// Available services
$runtime->scopeManager()          // ScopeManager instance
$runtime->tokenService()          // TokenService instance
$runtime->authorizationService()  // AuthorizationService instance
$runtime->clientService()         // ClientService instance
$runtime->clientRepository()      // ClientRepository instance
$runtime->tokenRepository()       // TokenRepository instance
$runtime->tokenGenerator()        // SecureTokenGenerator instance
$runtime->secretManager()         // ClientSecretManager instance
```

### Service Architecture

**Services** (Business Logic):
- `AuthorizationService` - Handles authorization code flow
- `TokenService` - Issues and validates tokens
- `ClientService` - Manages client registration and configuration

**Repositories** (Data Access):
- `ClientRepository` - Client CRUD operations
- `TokenRepository` - Token CRUD operations

**Utilities**:
- `ScopeManager` - Scope validation and user permission checks
- `SecureTokenGenerator` - Cryptographically secure token generation
- `ClientSecretManager` - Secret hashing and verification
- `PKCEValidator` - PKCE challenge/verifier validation

### Integration Points

**WordPress Hooks**:
- `plugins_loaded` - Initialize plugin services
- `rest_api_init` - Register REST API endpoints
- `parse_request` - Handle .well-known discovery endpoints
- `determine_current_user` - Authenticate OAuth tokens

**Filters**:
- `oauth_passport_scopes` - Customize available scopes
- `oauth_passport_authorization_server_metadata` - Modify discovery metadata
- `oauth_passport_protected_resource_metadata` - Modify resource metadata
- `oauth_passport_access_token_lifetime` - Customize token expiration
- `oauth_passport_refresh_token_lifetime` - Customize refresh token expiration

## Model Context Protocol (MCP) Support

OAuth Passport fully supports MCP authorization requirements. See [../llm-docks/MCP_REQUIREMENTS.md](../llm-docks/MCP_REQUIREMENTS.md) for complete details.

### Key MCP Features

1. **Protected Resource Metadata** - RFC 9728 endpoint for MCP server discovery
2. **Dynamic Client Registration** - RFC 7591 for automatic client setup
3. **Resource Indicators** - RFC 8707 for per-server token scoping
4. **PKCE Mandatory** - All flows require PKCE for security
5. **CORS Support** - Discovery endpoints support CORS for browser clients

### MCP Authorization Flow

```bash
# 1. Discover authorization server
curl https://mcp-server.example.com/.well-known/oauth-protected-resource

# 2. Register client dynamically
curl -X POST https://auth-server.example.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{"client_name": "MCP Client", "redirect_uris": ["https://client.example.com/callback"]}'

# 3. Authorization with resource parameter
GET /oauth-passport/v1/authorize?
  client_id=CLIENT_ID&
  resource=https://mcp-server.example.com&
  code_challenge=CHALLENGE&
  code_challenge_method=S256&
  response_type=code

# 4. Token request with resource
POST /oauth-passport/v1/token
  grant_type=authorization_code&
  code=AUTH_CODE&
  resource=https://mcp-server.example.com&
  code_verifier=VERIFIER
```

## Testing

Test the complete OAuth flow:

```bash
# 1. Register client
CLIENT_RESPONSE=$(curl -s -X POST https://yoursite.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{"client_name": "Test", "redirect_uris": ["http://localhost:3000"]}')

CLIENT_ID=$(echo $CLIENT_RESPONSE | jq -r '.client_id')
CLIENT_SECRET=$(echo $CLIENT_RESPONSE | jq -r '.client_secret')

# 2. Generate PKCE challenge
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | base64 | tr -d "=" | tr '/+' '_-')

# 3. Visit authorization URL (manual step)
echo "Visit: https://yoursite.com/wp-json/oauth-passport/v1/authorize?client_id=$CLIENT_ID&redirect_uri=http://localhost:3000&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&response_type=code"

# 4. Exchange code for token (after getting code from redirect)
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "code_verifier=$CODE_VERIFIER"
```

For troubleshooting common issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).