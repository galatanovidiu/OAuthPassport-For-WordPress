import { useState, useEffect } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { 
    Button,
    Modal,
    TextControl,
    CheckboxControl,
    Notice,
    Card,
    CardHeader,
    CardBody,
    CardFooter,
    Flex,
    FlexItem,
    __experimentalText as Text,
    __experimentalSpacer as Spacer,
    __experimentalConfirmDialog as ConfirmDialog
} from '@wordpress/components';
import apiFetch from '@wordpress/api-fetch';

const ClientsTab = () => {
    const [clients, setClients] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);
    const [newClient, setNewClient] = useState({
        client_name: '',
        redirect_uri: '',
        scopes: ['read', 'write']
    });
    const [generating, setGenerating] = useState(false);
    const [generatedClient, setGeneratedClient] = useState(null);
    const [deleteConfirm, setDeleteConfirm] = useState(null);

    const availableScopes = {
        'read': __('Read access to content', 'oauth-passport'),
        'write': __('Write access to content', 'oauth-passport'),
        'admin': __('Administrative access', 'oauth-passport'),
        'user': __('User profile access', 'oauth-passport')
    };

    useEffect(() => {
        loadClients();
    }, []);

    const loadClients = async () => {
        setLoading(true);
        try {
            const response = await apiFetch({
                path: '/oauth-passport/v1/admin/clients',
                method: 'GET'
            });
            setClients(response);
        } catch (error) {
            console.error('Failed to load clients:', error);
        } finally {
            setLoading(false);
        }
    };

    const generateClient = async () => {
        setGenerating(true);
        try {
            const response = await apiFetch({
                path: '/oauth-passport/v1/admin/clients',
                method: 'POST',
                data: {
                    client_name: newClient.client_name,
                    redirect_uri: newClient.redirect_uri,
                    scopes: newClient.scopes
                }
            });
            
            setGeneratedClient(response);
            setNewClient({ client_name: '', redirect_uri: '', scopes: ['read', 'write'] });
            setShowModal(false);
            await loadClients();
        } catch (error) {
            console.error('Failed to generate client:', error);
        } finally {
            setGenerating(false);
        }
    };

    const revokeClient = async (clientId) => {
        try {
            await apiFetch({
                path: `/oauth-passport/v1/admin/clients/${clientId}`,
                method: 'DELETE'
            });
            await loadClients();
        } catch (error) {
            console.error('Failed to revoke client:', error);
        }
        setDeleteConfirm(null);
    };

    const handleScopeChange = (scope, checked) => {
        setNewClient(prev => ({
            ...prev,
            scopes: checked 
                ? [...prev.scopes, scope]
                : prev.scopes.filter(s => s !== scope)
        }));
    };

    if (loading) {
        return <div>{__('Loading clients...', 'oauth-passport')}</div>;
    }

    return (
        <div className="oauth-clients">
            <Flex justify="space-between" align="center">
                <Text variant="title.small">{__('OAuth Clients', 'oauth-passport')}</Text>
                <Button 
                    variant="primary" 
                    onClick={() => setShowModal(true)}
                >
                    {__('Generate New Client', 'oauth-passport')}
                </Button>
            </Flex>

            <Spacer marginTop="24px" />

            {clients.length === 0 ? (
                <Card>
                    <CardBody>
                        <Text>{__('No OAuth clients registered.', 'oauth-passport')}</Text>
                    </CardBody>
                </Card>
            ) : (
                <div className="clients-grid">
                    {clients.map((client) => (
                        <Card key={client.client_id} className="client-card">
                            <CardHeader>
                                <Text weight="600">{client.client_name}</Text>
                            </CardHeader>
                            <CardBody>
                                <Flex direction="column" gap="8px">
                                    <FlexItem>
                                        <Text variant="caption">
                                            <strong>{__('Client ID:', 'oauth-passport')}</strong>
                                        </Text>
                                        <code style={{ display: 'block', background: '#f0f0f0', padding: '4px 8px', borderRadius: '4px', fontSize: '12px' }}>
                                            {client.client_id}
                                        </code>
                                    </FlexItem>
                                    <FlexItem>
                                        <Text variant="caption">
                                            <strong>{__('Redirect URIs:', 'oauth-passport')}</strong>
                                        </Text>
                                        <Text variant="caption">
                                            {JSON.parse(client.redirect_uris || '[]').join(', ')}
                                        </Text>
                                    </FlexItem>
                                    <FlexItem>
                                        <Text variant="caption">
                                            <strong>{__('Scopes:', 'oauth-passport')}</strong>
                                        </Text>
                                        <Text variant="caption">{client.scope}</Text>
                                    </FlexItem>
                                    <FlexItem>
                                        <Text variant="caption">
                                            <strong>{__('Created:', 'oauth-passport')}</strong>
                                        </Text>
                                        <Text variant="caption">
                                            {new Date(client.created_at).toLocaleDateString()}
                                        </Text>
                                    </FlexItem>
                                </Flex>
                            </CardBody>
                            <CardFooter>
                                <Button 
                                    variant="secondary" 
                                    isDestructive
                                    onClick={() => setDeleteConfirm(client)}
                                >
                                    {__('Revoke', 'oauth-passport')}
                                </Button>
                            </CardFooter>
                        </Card>
                    ))}
                </div>
            )}

            {/* Generate Client Modal */}
            {showModal && (
                <Modal
                    title={__('Generate New OAuth Client', 'oauth-passport')}
                    onRequestClose={() => setShowModal(false)}
                    size="medium"
                >
                    <div className="generate-client-form">
                        <TextControl
                            label={__('Client Name', 'oauth-passport')}
                            value={newClient.client_name}
                            onChange={(value) => setNewClient({ ...newClient, client_name: value })}
                            required
                        />
                        
                        <TextControl
                            label={__('Redirect URI', 'oauth-passport')}
                            type="url"
                            value={newClient.redirect_uri}
                            onChange={(value) => setNewClient({ ...newClient, redirect_uri: value })}
                            required
                        />

                        <div className="scopes-section">
                            <Text weight="600">{__('Scopes', 'oauth-passport')}</Text>
                            {Object.entries(availableScopes).map(([scope, description]) => (
                                <CheckboxControl
                                    key={scope}
                                    label={`${scope} - ${description}`}
                                    checked={newClient.scopes.includes(scope)}
                                    onChange={(checked) => handleScopeChange(scope, checked)}
                                />
                            ))}
                        </div>

                        <Flex justify="flex-end" gap="12px">
                            <Button 
                                variant="tertiary" 
                                onClick={() => setShowModal(false)}
                                disabled={generating}
                            >
                                {__('Cancel', 'oauth-passport')}
                            </Button>
                            <Button 
                                variant="primary" 
                                onClick={generateClient}
                                isBusy={generating}
                                disabled={generating || !newClient.client_name || !newClient.redirect_uri}
                            >
                                {generating ? __('Generating...', 'oauth-passport') : __('Generate Client', 'oauth-passport')}
                            </Button>
                        </Flex>
                    </div>
                </Modal>
            )}

            {/* Generated Client Modal */}
            {generatedClient && (
                <Modal
                    title={__('Client Generated Successfully', 'oauth-passport')}
                    onRequestClose={() => setGeneratedClient(null)}
                    size="medium"
                >
                    <Notice status="success" isDismissible={false}>
                        {__('Your OAuth client has been generated. Please save these credentials securely - the client secret will not be shown again.', 'oauth-passport')}
                    </Notice>
                    
                    <Spacer marginTop="16px" />
                    
                    <div className="generated-credentials">
                        <TextControl
                            label={__('Client ID', 'oauth-passport')}
                            value={generatedClient.client_id}
                            readOnly
                        />
                        <TextControl
                            label={__('Client Secret', 'oauth-passport')}
                            value={generatedClient.client_secret}
                            readOnly
                        />
                    </div>

                    <Flex justify="flex-end">
                        <Button 
                            variant="primary" 
                            onClick={() => setGeneratedClient(null)}
                        >
                            {__('Close', 'oauth-passport')}
                        </Button>
                    </Flex>
                </Modal>
            )}

            {/* Delete Confirmation */}
            {deleteConfirm && (
                <ConfirmDialog
                    isOpen={true}
                    onConfirm={() => revokeClient(deleteConfirm.client_id)}
                    onCancel={() => setDeleteConfirm(null)}
                    confirmButtonText={__('Revoke', 'oauth-passport')}
                    cancelButtonText={__('Cancel', 'oauth-passport')}
                >
                    {__('Are you sure you want to revoke this client? This action cannot be undone.', 'oauth-passport')}
                </ConfirmDialog>
            )}
        </div>
    );
};

export default ClientsTab; 