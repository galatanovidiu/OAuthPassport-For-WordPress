import { __ } from '@wordpress/i18n';
import { TabPanel, Card, CardHeader, CardBody } from '@wordpress/components';

import SettingsTab from './SettingsTab';
import ClientsTab from './ClientsTab';
import TokensTab from './TokensTab';

const AdminApp = () => {
	const tabs = [
		{
			name: 'settings',
			title: __( 'Settings', 'oauth-passport' ),
			className: 'oauth-settings-tab',
		},
		{
			name: 'clients',
			title: __( 'OAuth Clients', 'oauth-passport' ),
			className: 'oauth-clients-tab',
		},
		{
			name: 'tokens',
			title: __( 'Active Tokens', 'oauth-passport' ),
			className: 'oauth-tokens-tab',
		},
	];

	return (
		<div className="oauth-passport-admin">
			<Card>
				<CardHeader>
					<h1>{ __( 'OAuth Passport', 'oauth-passport' ) }</h1>
				</CardHeader>
				<CardBody>
					<TabPanel
						className="oauth-passport-tabs"
						activeClass="is-active"
						tabs={ tabs }
					>
						{ ( tab ) => {
							switch ( tab.name ) {
								case 'settings':
									return <SettingsTab />;
								case 'clients':
									return <ClientsTab />;
								case 'tokens':
									return <TokensTab />;
								default:
									return <SettingsTab />;
							}
						} }
					</TabPanel>
				</CardBody>
			</Card>
		</div>
	);
};

export default AdminApp;
