<?php
/**
 * Unit tests for ClientRepository class
 *
 * @package OAuthPassport
 * @subpackage Tests
 */

declare(strict_types=1);

namespace OAuthPassport\Tests\Unit;

use OAuthPassport\Repositories\ClientRepository;
use WP_UnitTestCase;

/**
 * Test ClientRepository class
 */
class ClientRepositoryTest extends WP_UnitTestCase
{
    /**
     * ClientRepository instance
     *
     * @var ClientRepository
     */
    private ClientRepository $repository;

    /**
     * Test client data
     *
     * @var array
     */
    private array $test_client_data;

    /**
     * Set up test fixtures
     */
    public function setUp(): void
    {
        parent::setUp();
        
        $this->repository = new ClientRepository();
        
        $this->test_client_data = [
            'client_id' => 'test_client_' . wp_generate_uuid4(),
            'client_secret_hash' => password_hash('test_secret_long_enough_32chars', PASSWORD_ARGON2ID),
            'client_name' => 'Test Client',
            'redirect_uris' => ['https://example.com/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'scope' => 'read write',
            'is_confidential' => true,
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql')
        ];
    }

    /**
     * Test storing a client
     */
    public function test_store_client(): void
    {
        $result = $this->repository->storeClient($this->test_client_data);
        
        $this->assertTrue($result);
        
        // Verify client was stored
        $stored_client = $this->repository->getClient($this->test_client_data['client_id']);
        $this->assertNotNull($stored_client);
        $this->assertEquals($this->test_client_data['client_name'], $stored_client['client_name']);
    }

    /**
     * Test retrieving a client
     */
    public function test_get_client(): void
    {
        // Store test client first
        $this->repository->storeClient($this->test_client_data);
        
        $client = $this->repository->getClient($this->test_client_data['client_id']);
        
        $this->assertNotNull($client);
        $this->assertEquals($this->test_client_data['client_id'], $client['client_id']);
        $this->assertEquals($this->test_client_data['client_name'], $client['client_name']);
        $this->assertIsArray($client['redirect_uris']);
        $this->assertIsArray($client['grant_types']);
    }

    /**
     * Test retrieving non-existent client
     */
    public function test_get_nonexistent_client(): void
    {
        $client = $this->repository->getClient('nonexistent_client');
        
        $this->assertNull($client);
    }

    /**
     * Test updating a client
     */
    public function test_update_client(): void
    {
        // Store test client first
        $this->repository->storeClient($this->test_client_data);
        
        $update_data = [
            'client_name' => 'Updated Test Client',
            'scope' => 'read write admin'
        ];
        
        $result = $this->repository->updateClient($this->test_client_data['client_id'], $update_data);
        $this->assertTrue($result);
        
        // Verify client was updated
        $updated_client = $this->repository->getClient($this->test_client_data['client_id']);
        $this->assertEquals('Updated Test Client', $updated_client['client_name']);
        $this->assertEquals('read write admin', $updated_client['scope']);
    }

    /**
     * Test deleting a client
     */
    public function test_delete_client(): void
    {
        // Store test client first
        $this->repository->storeClient($this->test_client_data);
        
        $result = $this->repository->deleteClient($this->test_client_data['client_id']);
        $this->assertTrue($result);
        
        // Verify client was deleted
        $deleted_client = $this->repository->getClient($this->test_client_data['client_id']);
        $this->assertNull($deleted_client);
    }

    /**
     * Test getting all clients
     */
    public function test_get_all_clients(): void
    {
        // Store multiple test clients
        $client1_data = $this->test_client_data;
        $client1_data['client_id'] = 'test_client_1_' . wp_generate_uuid4();
        $client1_data['client_name'] = 'Test Client 1';
        
        $client2_data = $this->test_client_data;
        $client2_data['client_id'] = 'test_client_2_' . wp_generate_uuid4();
        $client2_data['client_name'] = 'Test Client 2';
        
        $this->repository->storeClient($client1_data);
        $this->repository->storeClient($client2_data);
        
        $clients = $this->repository->getAllClients();
        
        $this->assertIsArray($clients);
        $this->assertGreaterThanOrEqual(2, count($clients));
        
        // Find our test clients in the results
        $found_client1 = false;
        $found_client2 = false;
        foreach ($clients as $client) {
            if ($client['client_id'] === $client1_data['client_id']) {
                $found_client1 = true;
            }
            if ($client['client_id'] === $client2_data['client_id']) {
                $found_client2 = true;
            }
        }
        
        $this->assertTrue($found_client1);
        $this->assertTrue($found_client2);
    }

    /**
     * Test getting all clients with pagination
     */
    public function test_get_all_clients_with_pagination(): void
    {
        // Store multiple test clients
        for ($i = 1; $i <= 5; $i++) {
            $client_data = $this->test_client_data;
            $client_data['client_id'] = 'test_client_' . $i . '_' . wp_generate_uuid4();
            $client_data['client_name'] = 'Test Client ' . $i;
            $this->repository->storeClient($client_data);
        }
        
        // Test pagination
        $clients_page1 = $this->repository->getAllClients(2, 0);
        $clients_page2 = $this->repository->getAllClients(2, 2);
        
        $this->assertIsArray($clients_page1);
        $this->assertIsArray($clients_page2);
        $this->assertLessThanOrEqual(2, count($clients_page1));
        $this->assertLessThanOrEqual(2, count($clients_page2));
        
        // Ensure different results between pages (if we have enough data)
        if (count($clients_page1) > 0 && count($clients_page2) > 0) {
            $this->assertNotEquals($clients_page1[0]['client_id'], $clients_page2[0]['client_id']);
        }
    }

    /**
     * Test rehashing client secret
     */
    public function test_rehash_client_secret(): void
    {
        // Store test client first
        $this->repository->storeClient($this->test_client_data);
        
        $new_secret_hash = password_hash('new_secret_long_enough_32chars', PASSWORD_ARGON2ID);
        
        $result = $this->repository->rehashClientSecret($this->test_client_data['client_id'], $new_secret_hash);
        $this->assertTrue($result);
        
        // Verify secret was updated
        $updated_client = $this->repository->getClient($this->test_client_data['client_id']);
        $this->assertNotNull($updated_client);
        $this->assertEquals($new_secret_hash, $updated_client['client_secret_hash']);
    }

    /**
     * Test storing client with complex data structures
     */
    public function test_complex_client_data(): void
    {
        $complex_client_data = $this->test_client_data;
        $complex_client_data['client_id'] = 'complex_test_client_' . wp_generate_uuid4();
        $complex_client_data['redirect_uris'] = [
            'https://example.com/callback',
            'https://example.com/callback2',
            'https://localhost:3000/callback'
        ];
        $complex_client_data['grant_types'] = ['authorization_code', 'refresh_token', 'client_credentials'];
        $complex_client_data['response_types'] = ['code', 'token'];
        
        $result = $this->repository->storeClient($complex_client_data);
        $this->assertTrue($result);
        
        $stored_client = $this->repository->getClient($complex_client_data['client_id']);
        $this->assertNotNull($stored_client);
        $this->assertCount(3, $stored_client['redirect_uris']);
        $this->assertCount(3, $stored_client['grant_types']);
        $this->assertCount(2, $stored_client['response_types']);
    }

    /**
     * Clean up after tests
     */
    public function tearDown(): void
    {
        parent::tearDown();
        
        // Clean up test data
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_clients WHERE client_id LIKE 'test_client_%'");
    }
}