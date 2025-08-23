import { useState, useEffect } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import {
	Button,
	Card,
	CardHeader,
	CardBody,
	CardFooter,
	Flex,
	FlexItem,
	__experimentalText as Text,
	__experimentalSpacer as Spacer,
	__experimentalConfirmDialog as ConfirmDialog,
	Notice,
} from '@wordpress/components';
import apiFetch from '@wordpress/api-fetch';

const TokensTab = () => {
	const [ tokens, setTokens ] = useState( [] );
	const [ loading, setLoading ] = useState( true );
	const [ revokeConfirm, setRevokeConfirm ] = useState( null );

	useEffect( () => {
		loadTokens();
	}, [] );

	const loadTokens = async () => {
		setLoading( true );
		try {
			const response = await apiFetch( {
				path: '/oauth-passport/v1/admin/tokens',
				method: 'GET',
			} );
			setTokens( response );
		} catch ( error ) {
			console.error( 'Failed to load tokens:', error );
		} finally {
			setLoading( false );
		}
	};

	const revokeToken = async ( tokenId ) => {
		try {
			await apiFetch( {
				path: `/oauth-passport/v1/admin/tokens/${ tokenId }`,
				method: 'DELETE',
			} );
			await loadTokens();
		} catch ( error ) {
			console.error( 'Failed to revoke token:', error );
		}
		setRevokeConfirm( null );
	};

	const formatDate = ( dateString ) => {
		return new Date( dateString ).toLocaleString();
	};

	const getTokenTypeColor = ( type ) => {
		switch ( type ) {
			case 'access':
				return '#007cba';
			case 'refresh':
				return '#00a32a';
			default:
				return '#666';
		}
	};

	const isExpiringSoon = ( expiresAt ) => {
		const now = new Date();
		const expires = new Date( expiresAt );
		const timeDiff = expires.getTime() - now.getTime();
		const hoursDiff = timeDiff / ( 1000 * 3600 );
		return hoursDiff <= 24 && hoursDiff > 0; // Expiring within 24 hours
	};

	const isExpired = ( expiresAt ) => {
		const now = new Date();
		const expires = new Date( expiresAt );
		return now > expires;
	};

	if ( loading ) {
		return <div>{ __( 'Loading tokens...', 'oauth-passport' ) }</div>;
	}

	return (
		<div className="oauth-tokens">
			<Flex justify="space-between" align="center">
				<Text variant="title.small">
					{ __( 'Active OAuth Tokens', 'oauth-passport' ) }
				</Text>
				<Button
					variant="secondary"
					onClick={ loadTokens }
					disabled={ loading }
				>
					{ __( 'Refresh', 'oauth-passport' ) }
				</Button>
			</Flex>

			<Spacer marginTop="24px" />

			<Notice status="info" isDismissible={ false }>
				{ __(
					'Note: Authorization codes and expired tokens are automatically cleaned up and not shown here.',
					'oauth-passport'
				) }
			</Notice>

			<Spacer marginTop="16px" />

			{ tokens.length === 0 ? (
				<Card>
					<CardBody>
						<Text>
							{ __(
								'No active tokens found.',
								'oauth-passport'
							) }
						</Text>
					</CardBody>
				</Card>
			) : (
				<div className="tokens-grid">
					{ tokens.map( ( token ) => (
						<Card
							key={ token.id }
							className={ `token-card ${
								isExpired( token.expires_at ) ? 'expired' : ''
							} ${
								isExpiringSoon( token.expires_at )
									? 'expiring-soon'
									: ''
							}` }
						>
							<CardHeader>
								<Flex justify="space-between" align="center">
									<Text weight="600">
										<span
											style={ {
												color: getTokenTypeColor(
													token.token_type
												),
												textTransform: 'capitalize',
											} }
										>
											{ token.token_type }
										</span>{ ' ' }
										Token
									</Text>
									{ isExpired( token.expires_at ) && (
										<span
											style={ {
												background: '#d63638',
												color: 'white',
												padding: '2px 8px',
												borderRadius: '12px',
												fontSize: '12px',
											} }
										>
											{ __(
												'Expired',
												'oauth-passport'
											) }
										</span>
									) }
									{ ! isExpired( token.expires_at ) &&
										isExpiringSoon( token.expires_at ) && (
											<span
												style={ {
													background: '#dba617',
													color: 'white',
													padding: '2px 8px',
													borderRadius: '12px',
													fontSize: '12px',
												} }
											>
												{ __(
													'Expiring Soon',
													'oauth-passport'
												) }
											</span>
										) }
								</Flex>
							</CardHeader>
							<CardBody>
								<Flex direction="column" gap="8px">
									<FlexItem>
										<Text variant="caption">
											<strong>
												{ __(
													'Client:',
													'oauth-passport'
												) }
											</strong>
										</Text>
										<Text variant="caption">
											{ token.client_name ||
												token.client_id }
										</Text>
									</FlexItem>
									<FlexItem>
										<Text variant="caption">
											<strong>
												{ __(
													'User:',
													'oauth-passport'
												) }
											</strong>
										</Text>
										<Text variant="caption">
											{ token.display_name ||
												`User #${ token.user_id }` }
										</Text>
									</FlexItem>
									<FlexItem>
										<Text variant="caption">
											<strong>
												{ __(
													'Scopes:',
													'oauth-passport'
												) }
											</strong>
										</Text>
										<Text variant="caption">
											{ token.scope || 'read write' }
										</Text>
									</FlexItem>
									<FlexItem>
										<Text variant="caption">
											<strong>
												{ __(
													'Created:',
													'oauth-passport'
												) }
											</strong>
										</Text>
										<Text variant="caption">
											{ formatDate( token.created_at ) }
										</Text>
									</FlexItem>
									<FlexItem>
										<Text variant="caption">
											<strong>
												{ __(
													'Expires:',
													'oauth-passport'
												) }
											</strong>
										</Text>
										<Text
											variant="caption"
											style={ {
												color: isExpired(
													token.expires_at
												)
													? '#d63638'
													: isExpiringSoon(
															token.expires_at
													  )
													? '#dba617'
													: 'inherit',
											} }
										>
											{ formatDate( token.expires_at ) }
										</Text>
									</FlexItem>
									<FlexItem>
										<Text variant="caption">
											<strong>
												{ __(
													'Token ID:',
													'oauth-passport'
												) }
											</strong>
										</Text>
										<code
											style={ {
												display: 'block',
												background: '#f0f0f0',
												padding: '4px 8px',
												borderRadius: '4px',
												fontSize: '11px',
												wordBreak: 'break-all',
											} }
										>
											{ token.id }
										</code>
									</FlexItem>
								</Flex>
							</CardBody>
							<CardFooter>
								<Button
									variant="secondary"
									isDestructive
									onClick={ () => setRevokeConfirm( token ) }
									size="small"
								>
									{ __( 'Revoke', 'oauth-passport' ) }
								</Button>
							</CardFooter>
						</Card>
					) ) }
				</div>
			) }

			{ /* Revoke Confirmation */ }
			{ revokeConfirm && (
				<ConfirmDialog
					isOpen={ true }
					onConfirm={ () => revokeToken( revokeConfirm.id ) }
					onCancel={ () => setRevokeConfirm( null ) }
					confirmButtonText={ __( 'Revoke', 'oauth-passport' ) }
					cancelButtonText={ __( 'Cancel', 'oauth-passport' ) }
				>
					<Text>
						{ __(
							'Are you sure you want to revoke this token? This action cannot be undone and will immediately invalidate the token.',
							'oauth-passport'
						) }
					</Text>
					<Spacer marginTop="12px" />
					<Text variant="caption">
						<strong>
							{ __( 'Token Type:', 'oauth-passport' ) }
						</strong>{ ' ' }
						{ revokeConfirm.token_type }
					</Text>
					<br />
					<Text variant="caption">
						<strong>{ __( 'Client:', 'oauth-passport' ) }</strong>{ ' ' }
						{ revokeConfirm.client_name || revokeConfirm.client_id }
					</Text>
					<br />
					<Text variant="caption">
						<strong>{ __( 'User:', 'oauth-passport' ) }</strong>{ ' ' }
						{ revokeConfirm.display_name ||
							`User #${ revokeConfirm.user_id }` }
					</Text>
				</ConfirmDialog>
			) }
		</div>
	);
};

export default TokensTab;
