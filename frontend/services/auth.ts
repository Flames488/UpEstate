/**
 * Authentication Service
 * Handles user authentication, session management, and user profile operations.
 * 
 * FRONTEND ↔ BACKEND SYNC CRITICAL: Ensure backend sends permissions explicitly.
 */

import { apiFetch } from "./api";
import { getCsrfHeader } from "./csrf";
import { TokenService } from "./token";

/**
 * Backend authentication response format
 * MUST MATCH BACKEND STRUCTURE EXACTLY for proper sync
 */
export interface BackendAuthResponse {
  id: string;
  role: string;
  permissions: string[];
  tenant_id: string;
  plan: string;
  // Optional fields for token management
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
}

/**
 * Frontend AuthUser type
 * Normalized from backend response with consistent naming conventions
 */
export type AuthUser = {
  id: string;
  role: string;
  permissions: string[];
  tenantId: string;
  plan: string;
};

/**
 * Login request payload
 */
interface LoginRequest {
  email: string;
  password: string;
}

/**
 * Login response data
 */
interface LoginResponse {
  user: AuthUser;
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}

/**
 * Authentication error types
 */
export enum AuthErrorType {
  INVALID_CREDENTIALS = "INVALID_CREDENTIALS",
  ACCOUNT_LOCKED = "ACCOUNT_LOCKED",
  NETWORK_ERROR = "NETWORK_ERROR",
  INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS",
  SESSION_EXPIRED = "SESSION_EXPIRED",
  UNKNOWN = "UNKNOWN"
}

/**
 * Custom authentication error class
 */
export class AuthError extends Error {
  constructor(
    message: string,
    public type: AuthErrorType = AuthErrorType.UNKNOWN,
    public statusCode?: number,
    public userData?: Partial<AuthUser>
  ) {
    super(message);
    this.name = "AuthError";
  }
}

/**
 * Normalizes backend user data to frontend AuthUser format
 * Critical for ensuring consistent property naming across the application
 * 
 * @param backendUser - Raw user data from backend API
 * @returns Normalized AuthUser object
 */
function normalizeUserData(backendUser: BackendAuthResponse): AuthUser {
  // Map backend snake_case to frontend camelCase
  return {
    id: backendUser.id,
    role: backendUser.role,
    permissions: backendUser.permissions || [], // Ensure permissions is always an array
    tenantId: backendUser.tenant_id,
    plan: backendUser.plan
  };
}

/**
 * Validates that the backend response contains all required user data
 * 
 * @param data - Backend response to validate
 * @throws {AuthError} If required data is missing
 */
function validateAuthResponse(data: any): asserts data is BackendAuthResponse {
  const requiredFields = ['id', 'role', 'permissions', 'tenant_id', 'plan'];
  const missingFields = requiredFields.filter(field => !data[field]);
  
  if (missingFields.length > 0) {
    throw new AuthError(
      `Backend response missing required fields: ${missingFields.join(', ')}`,
      AuthErrorType.UNKNOWN
    );
  }
  
  // Validate permissions is an array
  if (!Array.isArray(data.permissions)) {
    throw new AuthError(
      'Permissions must be an array',
      AuthErrorType.UNKNOWN
    );
  }
}

/**
 * Authenticates a user with email and password
 * 
 * @param email - User's email address
 * @param password - User's password
 * @returns Promise resolving to the authenticated user data
 * @throws {AuthError} If authentication fails
 */
export async function login(email: string, password: string): Promise<AuthUser> {
  try {
    const response = await apiFetch<BackendAuthResponse>("/auth/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...getCsrfHeader(),
      },
      body: JSON.stringify({ email, password }),
    });

    // Validate backend response structure
    validateAuthResponse(response);

    if (!response.access_token) {
      throw new AuthError(
        "No access token received from backend",
        AuthErrorType.UNKNOWN
      );
    }

    // Store the authentication token
    TokenService.setAccessToken(response.access_token);
    
    if (response.refresh_token) {
      TokenService.setRefreshToken(response.refresh_token);
    }

    // Normalize backend data to frontend format
    const normalizedUser = normalizeUserData(response);
    
    // Store user data for quick access (optional)
    if (typeof window !== 'undefined') {
      localStorage.setItem('auth_user', JSON.stringify(normalizedUser));
    }

    return normalizedUser;
  } catch (error: unknown) {
    if (error instanceof AuthError) {
      throw error;
    }
    
    if (error instanceof Error) {
      if (error.message.includes("401") || error.message.includes("Invalid credentials")) {
        throw new AuthError(
          "Invalid email or password",
          AuthErrorType.INVALID_CREDENTIALS,
          401
        );
      }
      if (error.message.includes("403") || error.message.includes("locked")) {
        throw new AuthError(
          "Account is temporarily locked",
          AuthErrorType.ACCOUNT_LOCKED,
          403
        );
      }
      if (error.message.includes("Network Error")) {
        throw new AuthError(
          "Network error. Please check your connection.",
          AuthErrorType.NETWORK_ERROR
        );
      }
      throw new AuthError(error.message, AuthErrorType.UNKNOWN);
    }
    throw new AuthError("An unknown error occurred during login");
  }
}

/**
 * Logs out the current user by invalidating the session
 * 
 * @returns Promise that resolves when logout is complete
 * @throws {Error} If logout fails
 */
export async function logout(): Promise<void> {
  try {
    await apiFetch("/auth/logout", {
      method: "POST",
      headers: getCsrfHeader(),
    });
  } catch (error: unknown) {
    console.warn("Logout API call failed, but clearing local session anyway:", error);
  } finally {
    // Always clear local tokens and user data even if API call fails
    TokenService.clearTokens();
    if (typeof window !== 'undefined') {
      localStorage.removeItem('auth_user');
      sessionStorage.removeItem('auth_user');
    }
  }
}

/**
 * Retrieves the currently authenticated user's profile
 * 
 * @returns Promise resolving to the current user data
 * @throws {AuthError} If user is not authenticated or token is invalid
 */
export async function getMe(): Promise<AuthUser> {
  try {
    const response = await apiFetch<BackendAuthResponse>("/auth/me");
    
    // Validate backend response structure
    validateAuthResponse(response);
    
    // Normalize backend data to frontend format
    const normalizedUser = normalizeUserData(response);
    
    // Cache the user data
    if (typeof window !== 'undefined') {
      localStorage.setItem('auth_user', JSON.stringify(normalizedUser));
    }
    
    return normalizedUser;
  } catch (error: unknown) {
    if (error instanceof Error && error.message.includes("401")) {
      // Token might be expired, clear it
      TokenService.clearTokens();
      if (typeof window !== 'undefined') {
        localStorage.removeItem('auth_user');
      }
      throw new AuthError(
        "Session expired. Please log in again.",
        AuthErrorType.SESSION_EXPIRED,
        401
      );
    }
    
    // Handle permission-related errors
    if (error instanceof Error && error.message.includes("403")) {
      throw new AuthError(
        "Insufficient permissions to access this resource",
        AuthErrorType.INSUFFICIENT_PERMISSIONS,
        403
      );
    }
    
    throw error;
  }
}

/**
 * Gets the cached user data if available
 * Useful for immediate UI updates without API call
 * 
 * @returns Cached user data or null if not available
 */
export function getCachedUser(): AuthUser | null {
  if (typeof window === 'undefined') return null;
  
  const cached = localStorage.getItem('auth_user') || sessionStorage.getItem('auth_user');
  if (cached) {
    try {
      return JSON.parse(cached) as AuthUser;
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Checks if user has specific permission
 * 
 * @param permission - Permission to check
 * @returns boolean indicating if user has permission
 */
export function hasPermission(permission: string): boolean {
  const user = getCachedUser();
  return user ? user.permissions.includes(permission) : false;
}

/**
 * Checks if user has any of the specified permissions
 * 
 * @param permissions - Array of permissions to check
 * @returns boolean indicating if user has any of the permissions
 */
export function hasAnyPermission(permissions: string[]): boolean {
  const user = getCachedUser();
  return user ? permissions.some(permission => user.permissions.includes(permission)) : false;
}

/**
 * Checks if user has all of the specified permissions
 * 
 * @param permissions - Array of permissions to check
 * @returns boolean indicating if user has all of the permissions
 */
export function hasAllPermissions(permissions: string[]): boolean {
  const user = getCachedUser();
  return user ? permissions.every(permission => user.permissions.includes(permission)) : false;
}

/**
 * Refreshes the authentication token using a refresh token
 * 
 * @returns Promise resolving to the new token data
 * @throws {AuthError} If token refresh fails
 */
export async function refreshToken(): Promise<{ access_token: string }> {
  const refreshToken = TokenService.getRefreshToken();
  
  if (!refreshToken) {
    throw new AuthError(
      "No refresh token available",
      AuthErrorType.SESSION_EXPIRED
    );
  }

  try {
    const response = await apiFetch<{ access_token: string }>("/auth/refresh", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...getCsrfHeader(),
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!response.access_token) {
      throw new AuthError(
        "No access token received from refresh",
        AuthErrorType.UNKNOWN
      );
    }

    TokenService.setAccessToken(response.access_token);
    return response;
  } catch (error: unknown) {
    // Clear tokens on refresh failure
    TokenService.clearTokens();
    if (typeof window !== 'undefined') {
      localStorage.removeItem('auth_user');
    }
    
    if (error instanceof Error) {
      if (error.message.includes("401") || error.message.includes("Invalid token")) {
        throw new AuthError(
          "Refresh token expired or invalid. Please log in again.",
          AuthErrorType.SESSION_EXPIRED,
          401
        );
      }
      throw new AuthError(
        `Token refresh failed: ${error.message}`,
        AuthErrorType.UNKNOWN
      );
    }
    throw new AuthError("Token refresh failed due to unknown error");
  }
}

/**
 * Checks if the user is currently authenticated
 * 
 * @returns boolean indicating authentication status
 */
export function isAuthenticated(): boolean {
  return TokenService.hasValidToken();
}

/**
 * Gets user's current plan
 * 
 * @returns Current plan or null if not available
 */
export function getCurrentPlan(): string | null {
  const user = getCachedUser();
  return user ? user.plan : null;
}

/**
 * Gets user's tenant ID
 * 
 * @returns Tenant ID or null if not available
 */
export function getTenantId(): string | null {
  const user = getCachedUser();
  return user ? user.tenantId : null;
}

/**
 * Authentication service object
 */
export const AuthService = {
  login,
  logout,
  getMe,
  getCachedUser,
  refreshToken,
  isAuthenticated,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  getCurrentPlan,
  getTenantId,
};

export default AuthService;