import axios from 'axios';

/**
 * Axios instance configured for Secure API communication.
 * <p>
 * Base URL: https://localhost:8443/api
 * </p>
 */
const api = axios.create({
  baseURL: 'https://localhost:8443/api',
});

/**
 * Utility to inject the OIDC Access Token into every outgoing API request.
 * <p>
 * This ensures that:
 * 1. All requests are authenticated via "Bearer" token.
 * 2. If the token is cleared (logout), headers are cleaned up to prevent leakage.
 * </p>
 *
 * @param {string | undefined} token - The raw JWT access token string.
 */
export const setAuthToken = (token: string | undefined) => {
  if (token) {
    // Attach token to the Authorization header
    api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  } else {
    // Remove header to prevent using stale tokens
    delete api.defaults.headers.common['Authorization'];
  }
};

export default api;
