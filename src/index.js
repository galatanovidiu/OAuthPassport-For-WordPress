import { render } from '@wordpress/element';
import { __ } from '@wordpress/i18n';
import AdminApp from './components/AdminApp';

import './style.css';

// Function to mount the React app
function mountApp() {
    console.log('Attempting to mount OAuth Passport admin app...');
    console.log('Document ready state:', document.readyState);
    
    const container = document.getElementById('oauth-passport-admin-root');
    console.log('Container element found:', container);
    
    if (container) {
        console.log('Mounting React app...');
        render(<AdminApp />, container);
        console.log('React app mounted successfully!');
    } else {
        console.error('Container element #oauth-passport-admin-root not found');
    }
}

// Mount app when DOM is ready
console.log('OAuth Passport script loaded, document ready state:', document.readyState);

if (document.readyState === 'loading') {
    console.log('DOM still loading, adding event listener...');
    document.addEventListener('DOMContentLoaded', mountApp);
} else {
    console.log('DOM already ready, mounting immediately...');
    mountApp();
} 