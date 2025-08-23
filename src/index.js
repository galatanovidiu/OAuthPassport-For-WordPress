import { render } from '@wordpress/element';
import AdminApp from './components/AdminApp';

import './style.css';

// Function to mount the React app
function mountApp() {
	const container = document.getElementById( 'oauth-passport-admin-root' );

	if ( container ) {
		render( <AdminApp />, container );
	}
}

// Mount app when DOM is ready
if ( document.readyState === 'loading' ) {
	document.addEventListener( 'DOMContentLoaded', mountApp );
} else {
	mountApp();
}
