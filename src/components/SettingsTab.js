import { useState, useEffect } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import { 
    Panel,
    PanelBody,
    PanelRow,
    ToggleControl,
    RangeControl,
    Button,
    Notice,
    Card,
    CardHeader,
    CardBody,
    Flex,
    FlexItem,
    __experimentalText as Text,
    __experimentalSpacer as Spacer
} from '@wordpress/components';
import apiFetch from '@wordpress/api-fetch';

const SettingsTab = () => {
    const [settings, setSettings] = useState({
        oauth_passport_enabled: true,
        oauth_passport_access_token_lifetime: 3600,
        oauth_passport_refresh_token_lifetime: 2592000
    });
    const [saving, setSaving] = useState(false);
    const [saveMessage, setSaveMessage] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    useEffect(() => {
        // Load current settings
        loadSettings();
    }, []);

    const loadSettings = async () => {
        setLoading(true);
        setError('');
        
        try {
            const response = await apiFetch({
                path: '/wp/v2/settings',
                method: 'GET'
            });
            
            setSettings({
                oauth_passport_enabled: response.oauth_passport_enabled ?? true,
                oauth_passport_access_token_lifetime: response.oauth_passport_access_token_lifetime ?? 3600,
                oauth_passport_refresh_token_lifetime: response.oauth_passport_refresh_token_lifetime ?? 2592000
            });
        } catch (error) {
            console.error('Failed to load settings:', error);
            setError(__('Failed to load settings. Using defaults.', 'oauth-passport'));
        } finally {
            setLoading(false);
        }
    };

    const saveSettings = async () => {
        setSaving(true);
        setSaveMessage('');

        try {
            await apiFetch({
                path: '/wp/v2/settings',
                method: 'POST',
                data: settings
            });
            setSaveMessage(__('Settings saved successfully!', 'oauth-passport'));
        } catch (error) {
            setSaveMessage(__('Failed to save settings. Please try again.', 'oauth-passport'));
            console.error('Failed to save settings:', error);
        } finally {
            setSaving(false);
        }
    };

    const endpoints = [
        {
            name: __('Authorization', 'oauth-passport'),
            url: `${window.wpApiSettings?.root || '/wp-json/'}oauth-passport/v1/authorize`
        },
        {
            name: __('Token', 'oauth-passport'),
            url: `${window.wpApiSettings?.root || '/wp-json/'}oauth-passport/v1/token`
        },
        {
            name: __('Registration', 'oauth-passport'),
            url: `${window.wpApiSettings?.root || '/wp-json/'}oauth-passport/v1/register`
        },
        {
            name: __('JWKS', 'oauth-passport'),
            url: `${window.wpApiSettings?.root || '/wp-json/'}oauth-passport/v1/jwks`
        },
        {
            name: __('Discovery (Authorization Server)', 'oauth-passport'),
            url: `${window.location.origin}/.well-known/oauth-authorization-server`
        },
        {
            name: __('Discovery (Protected Resource)', 'oauth-passport'),
            url: `${window.location.origin}/.well-known/oauth-protected-resource`
        }
    ];

    if (loading) {
        return (
            <div style={{ padding: '20px', textAlign: 'center' }}>
                <Text>{__('Loading settings...', 'oauth-passport')}</Text>
            </div>
        );
    }

    return (
        <div className="oauth-settings">
            {error && (
                <Notice status="warning" isDismissible={true} onRemove={() => setError('')}>
                    {error}
                </Notice>
            )}
            
            <Panel>
                <PanelBody title={__('OAuth Configuration', 'oauth-passport')} initialOpen={true}>
                    <PanelRow>
                        <ToggleControl
                            label={__('Enable OAuth', 'oauth-passport')}
                            help={__('Enable OAuth 2.1 authentication for WordPress REST API', 'oauth-passport')}
                            checked={settings.oauth_passport_enabled}
                            onChange={(value) => setSettings({ ...settings, oauth_passport_enabled: value })}
                        />
                    </PanelRow>
                    
                    <PanelRow>
                        <RangeControl
                            label={__('Access Token Lifetime (seconds)', 'oauth-passport')}
                            help={__('Access token lifetime in seconds (default: 3600 = 1 hour)', 'oauth-passport')}
                            value={settings.oauth_passport_access_token_lifetime}
                            onChange={(value) => setSettings({ ...settings, oauth_passport_access_token_lifetime: value })}
                            min={300}
                            max={86400}
                            step={300}
                        />
                    </PanelRow>

                    <PanelRow>
                        <RangeControl
                            label={__('Refresh Token Lifetime (seconds)', 'oauth-passport')}
                            help={__('Refresh token lifetime in seconds (default: 2592000 = 30 days)', 'oauth-passport')}
                            value={settings.oauth_passport_refresh_token_lifetime}
                            onChange={(value) => setSettings({ ...settings, oauth_passport_refresh_token_lifetime: value })}
                            min={86400}
                            max={31536000}
                            step={86400}
                        />
                    </PanelRow>

                    <PanelRow>
                        <Button 
                            variant="primary" 
                            onClick={saveSettings}
                            isBusy={saving}
                            disabled={saving}
                        >
                            {saving ? __('Saving...', 'oauth-passport') : __('Save Settings', 'oauth-passport')}
                        </Button>
                    </PanelRow>

                    {saveMessage && (
                        <PanelRow>
                            <Notice 
                                status={saveMessage.includes('success') ? 'success' : 'error'}
                                isDismissible={true}
                                onRemove={() => setSaveMessage('')}
                            >
                                {saveMessage}
                            </Notice>
                        </PanelRow>
                    )}
                </PanelBody>
            </Panel>

            <Spacer marginTop="24px" />

            <Card>
                <CardHeader>
                    <Text variant="title.small">{__('OAuth Endpoints', 'oauth-passport')}</Text>
                </CardHeader>
                <CardBody>
                    {endpoints.map((endpoint, index) => (
                        <Flex key={index} align="center" gap="16px" style={{ marginBottom: '12px' }}>
                            <FlexItem>
                                <Text weight="600">{endpoint.name}:</Text>
                            </FlexItem>
                            <FlexItem>
                                <code style={{ background: '#f0f0f0', padding: '4px 8px', borderRadius: '4px', fontSize: '12px' }}>
                                    {endpoint.url}
                                </code>
                            </FlexItem>
                        </Flex>
                    ))}
                </CardBody>
            </Card>
        </div>
    );
};

export default SettingsTab; 