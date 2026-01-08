export const authConfig = {
  authority: "https://localhost:8444/realms/SecureExchange",
  client_id: "secure-app", // Matches the Client ID you created in Keycloak
  redirect_uri: "https://localhost:5173", // Vite now runs on HTTPS
  response_type: "code",
  scope: "openid profile email",
  automaticSilentRenew: true,
  // Point silent redirect to the same app; we will handle it in main.jsx
  silent_redirect_uri: window.location.origin,
  post_logout_redirect_uri: "https://localhost:5173",
  onSigninCallback: () => {
    window.history.replaceState({}, document.title, window.location.pathname);
  },
};
