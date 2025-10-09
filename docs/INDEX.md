# OAuth Passport Documentation

Welcome to the OAuth Passport documentation. This folder contains all the documentation you need to get started with OAuth Passport.

## Documentation Structure

📖 **[README.md](README.md)** - Complete setup and usage guide
- Installation instructions
- Quick start examples with PKCE
- OAuth scopes and configuration
- Developer integration with Runtime API

🔧 **[TECHNICAL.md](TECHNICAL.md)** - Technical reference and API documentation
- OAuth 2.1 server implementation details
- Complete API endpoints reference
- Runtime services access
- Database schema and security features
- Standards compliance (RFC 7591, 7636, 8414, 8707, 9728)

🚨 **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues and solutions
- Quick diagnostics checklist
- Error reference guide
- Step-by-step debugging
- Testing procedures and database queries

📋 **[PHPSTAN_WORDPRESS.md](PHPSTAN_WORDPRESS.md)** - PHPStan configuration
- Static analysis setup for WordPress development
- WordPress-specific patterns and type handling

## Getting Started

1. **New to OAuth Passport?** Start with [README.md](README.md)
2. **Need detailed API info?** Check [TECHNICAL.md](TECHNICAL.md)
3. **Having issues?** See [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
4. **Implementing MCP?** See [../llm-docks/MCP_REQUIREMENTS.md](../llm-docks/MCP_REQUIREMENTS.md)

## Quick Links

- **Installation**: [README.md#installation](README.md#installation)
- **Register Client**: [README.md#register-your-first-client](README.md#register-your-first-client)
- **API Endpoints**: [TECHNICAL.md#api-endpoints](TECHNICAL.md#api-endpoints)
- **Runtime Services**: [TECHNICAL.md#runtime-access](TECHNICAL.md#runtime-access)
- **WP-CLI Commands**: [TECHNICAL.md#wp-cli-commands](TECHNICAL.md#wp-cli-commands)
- **Common Errors**: [TROUBLESHOOTING.md#common-errors](TROUBLESHOOTING.md#common-errors)

## Key Features

✅ **OAuth 2.1 Compliant** - Full implementation with mandatory PKCE  
✅ **Dynamic Client Registration** - RFC 7591 compliant  
✅ **Resource Indicators** - RFC 8707 support  
✅ **Discovery Endpoints** - RFC 8414 & RFC 9728  
✅ **MCP Authorization** - Model Context Protocol support  
✅ **Opaque Tokens** - Secure, revocable tokens stored in database

---

**Need more help?** 
- Main plugin docs: [../README.md](../README.md)
- Developer guide: [../AGENTS.md](../AGENTS.md)
- MCP specifications: [../llm-docks/](../llm-docks/)