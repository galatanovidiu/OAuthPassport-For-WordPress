<?php
/**
 * Plugin Runtime Registry
 *
 * Provides read-only access to the core services that power the OAuth
 * Passport plugin so other components can collaborate without a service
 * container or static facade.
 *
 * @package OAuthPassport
 * @subpackage Runtime
 */

declare( strict_types=1 );

namespace OAuthPassport\Runtime;

use OAuthPassport\Auth\ClientSecretManager;
use OAuthPassport\Auth\ScopeManager;
use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Repositories\ClientRepository;
use OAuthPassport\Repositories\TokenRepository;
use OAuthPassport\Services\AuthorizationService;
use OAuthPassport\Services\ClientService;
use OAuthPassport\Services\TokenService;

class Runtime {
	public function __construct(
		private ScopeManager $scope_manager,
		private TokenService $token_service,
		private AuthorizationService $authorization_service,
		private ClientService $client_service,
		private ClientRepository $client_repository,
		private TokenRepository $token_repository,
		private SecureTokenGenerator $token_generator,
		private ClientSecretManager $secret_manager
	) {}

	public function scopeManager(): ScopeManager {
		return $this->scope_manager;
	}

	public function tokenService(): TokenService {
		return $this->token_service;
	}

	public function authorizationService(): AuthorizationService {
		return $this->authorization_service;
	}

	public function clientService(): ClientService {
		return $this->client_service;
	}

	public function clientRepository(): ClientRepository {
		return $this->client_repository;
	}

	public function tokenRepository(): TokenRepository {
		return $this->token_repository;
	}

	public function tokenGenerator(): SecureTokenGenerator {
		return $this->token_generator;
	}

	public function secretManager(): ClientSecretManager {
		return $this->secret_manager;
	}
}
