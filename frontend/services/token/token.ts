// frontend/services/auth/token.ts
const TOKEN_KEY = "auth_token";
const REFRESH_TOKEN_KEY = "refresh_token";

// Get token from localStorage
export const getToken = (): string | null => {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
};

// Get refresh token
export const getRefreshToken = (): string | null => {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REFRESH_TOKEN_KEY);
};

// Set tokens
export const setTokens = (token: string, refreshToken?: string): void => {
  if (typeof window === "undefined") return;
  localStorage.setItem(TOKEN_KEY, token);
  if (refreshToken) {
    localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  }
};

// Clear tokens
export const clearToken = (): void => {
  if (typeof window === "undefined") return;
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
};

// Check if token exists
export const hasToken = (): boolean => {
  return !!getToken();
};