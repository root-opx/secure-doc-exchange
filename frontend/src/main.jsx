import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import { AuthProvider } from 'react-oidc-context';
import { authConfig } from './authConfig';
import './index.css'; // Global Styles

import { UserManager } from 'oidc-client-ts';

// Handle Silent Renew Callback (Hidden Iframe)
if (window.parent !== window && window.location.href.includes("code=")) {
  console.log("Silent Renew Callback Detected");
  new UserManager({}) // Empty config is fine for callback
    .signinSilentCallback()
    .then(() => { console.log("Silent Renew Configured"); })
    .catch(err => { console.error("Silent Renew Error", err); });

  // Stop the rest of the app from rendering in the iframe
} else {
  ReactDOM.createRoot(document.getElementById('root')).render(
    <React.StrictMode>
      <AuthProvider {...authConfig}>
        <App />
      </AuthProvider>
    </React.StrictMode>,
  );
}
