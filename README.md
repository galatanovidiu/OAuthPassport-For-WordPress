# OAuth Passport

[![WordPress Plugin Version](https://img.shields.io/badge/WordPress-6.4%2B-blue.svg)](https://wordpress.org/)
[![PHP Version](https://img.shields.io/badge/PHP-8.0%2B-purple.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Alpha%20%28Experimental%29-orange.svg)](https://github.com/galatanovidiu/oauth-passport/releases)

Transform your WordPress site into a secure OAuth 2.1 authorization server.

> **⚠️ EXPERIMENTAL ALPHA RELEASE**  
> This plugin is in active development and intended for **testing and development only**.  
> **DO NOT use in production environments.** APIs and features may change significantly between versions.

## What is OAuth Passport?

OAuth Passport enables your WordPress site to act as an OAuth provider, allowing third-party applications to authenticate users and access your APIs through secure, standards-compliant OAuth flows.

**MCP Compliant**: OAuth Passport is fully compliant with the [Model Context Protocol (MCP) Authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization), making it ideal for building MCP servers that require OAuth 2.1 authorization.

Perfect for:
- **MCP Servers** - Authorization server for Model Context Protocol implementations
- **Mobile Apps** - Secure authentication for iOS/Android apps
- **Desktop Applications** - OAuth integration for desktop software  
- **API Access** - Controlled access to WordPress REST API
- **Third-party Integrations** - Allow external services to connect
- **Single Sign-On** - Use WordPress as identity provider

## Key Features

✅ **OAuth 2.1 Compliant** - Full implementation with mandatory PKCE  
✅ **Dynamic Client Registration** - Self-service client registration (RFC 7591)  
✅ **Discovery Endpoints** - Automatic configuration discovery  
✅ **WordPress Integration** - Seamless user system integration  
✅ **Admin Interface** - React-based management panel  
✅ **Secure by Default** - HTTPS enforcement, token rotation, rate limiting

## Quick Start

### Installation
1. Upload plugin to `/wp-content/plugins/oauth-passport`
2. Activate through WordPress admin
3. Configure at **Settings > OAuth Passport**

### Register Your First Client
```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://myapp.com/callback"]
  }'
```

### Authorization Flow
1. Direct users to authorization URL with PKCE
2. Exchange authorization code for access token
3. Use Bearer token for API access

## Documentation

📖 **[Complete Documentation](docs/README.md)** - Full setup and usage guide  
🔧 **[Technical Reference](docs/TECHNICAL.md)** - API endpoints and integration  
🚨 **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

## Requirements

- WordPress 6.4+
- PHP 8.0+
- MySQL 5.7+ / MariaDB 10.3+
- HTTPS (required in production)
- Pretty permalinks enabled

## Standards Compliance

OAuth Passport implements the complete OAuth 2.1 specification and is fully compliant with [MCP Authorization requirements](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization#overview):

- ✅ OAuth 2.1 ([draft-ietf-oauth-v2-1-13](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13))
- ✅ RFC 7636 (PKCE - Mandatory)
- ✅ RFC 7591 (Dynamic Client Registration)
- ✅ RFC 8414 (Authorization Server Metadata)
- ✅ RFC 9728 (Protected Resource Metadata)
- ✅ RFC 8707 (Resource Indicators)
- ✅ Model Context Protocol Authorization Specification

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- 📚 **Documentation**: [docs/](docs/) folder
- 🐛 **Issues**: Report on GitHub

---

**Made with ❤️ for the WordPress community**
