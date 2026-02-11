// frontend/services/api.ts
import axios from "axios";
import { getToken, clearToken } from "./auth/token";
import type { ApiResponse, ApiError } from "../types/api";

// Environment configuration
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  import.meta.env.VITE_API_URL ||
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  "http://localhost:5000/api/v1";

// ==================== Axios Instance ====================
export const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  timeout: 15000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request interceptor for adding auth token
api.interceptors.request.use(
  (config) => {
    const token = getToken();
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for handling errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle unauthorized access
    if (error.response?.status === 401) {
      clearToken();
      // Redirect to login with return URL
      const currentPath = window.location.pathname + window.location.search;
      if (currentPath !== "/login") {
        window.location.href = `/login?redirect=${encodeURIComponent(currentPath)}`;
      }
    }

    // Handle network errors
    if (!error.response) {
      return Promise.reject({
        message: "Network error. Please check your connection.",
        status: 0,
      });
    }

    // Handle server errors
    return Promise.reject({
      message: error.response.data?.message || "An error occurred",
      status: error.response.status,
      data: error.response.data,
    });
  }
);

// ==================== Fetch Wrapper ====================
export async function apiFetch<T = any>(
  url: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const fullUrl = `${API_BASE_URL}${url}`;

  try {
    const response = await fetch(fullUrl, {
      ...options,
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        // Add Authorization header if token exists
        ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {}),
        ...(options.headers || {}),
      },
    });

    // Handle unauthorized access
    if (response.status === 401) {
      clearToken();
      const currentPath = window.location.pathname + window.location.search;
      if (currentPath !== "/login") {
        window.location.href = `/login?redirect=${encodeURIComponent(currentPath)}`;
      }
      throw {
        message: "Unauthorized access",
        status: 401,
      };
    }

    // Parse response
    const data = await response.json();

    if (!response.ok) {
      throw {
        message: data.message || `HTTP error! status: ${response.status}`,
        status: response.status,
        data,
      };
    }

    return {
      data,
      status: response.status,
      success: true,
    };
  } catch (error) {
    // Handle network errors
    if (error instanceof TypeError && error.message === "Failed to fetch") {
      throw {
        message: "Network error. Please check your connection.",
        status: 0,
      };
    }

    throw error;
  }
}

// ==================== Enhanced API Service ====================
export class ApiService {
  // Generic GET request
  static async get<T = any>(url: string, params?: Record<string, any>): Promise<T> {
    const response = await api.get<T>(url, { params });
    return response.data;
  }

  // Generic POST request
  static async post<T = any>(url: string, data?: any): Promise<T> {
    const response = await api.post<T>(url, data);
    return response.data;
  }

  // Generic PUT request
  static async put<T = any>(url: string, data?: any): Promise<T> {
    const response = await api.put<T>(url, data);
    return response.data;
  }

  // Generic PATCH request
  static async patch<T = any>(url: string, data?: any): Promise<T> {
    const response = await api.patch<T>(url, data);
    return response.data;
  }

  // Generic DELETE request
  static async delete<T = any>(url: string): Promise<T> {
    const response = await api.delete<T>(url);
    return response.data;
  }

  // Upload file
  static async upload<T = any>(
    url: string,
    file: File,
    onProgress?: (progress: number) => void
  ): Promise<T> {
    const formData = new FormData();
    formData.append("file", file);

    const response = await api.post<T>(url, formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
      onUploadProgress: (progressEvent) => {
        if (onProgress && progressEvent.total) {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          onProgress(progress);
        }
      },
    });

    return response.data;
  }

  // Fetch with retry logic
  static async fetchWithRetry<T = any>(
    url: string,
    options: RequestInit = {},
    maxRetries = 3
  ): Promise<ApiResponse<T>> {
    let lastError: any;

    for (let i = 0; i < maxRetries; i++) {
      try {
        return await apiFetch<T>(url, options);
      } catch (error) {
        lastError = error;
        
        // Don't retry on 4xx errors (except 429 - Too Many Requests)
        if (error.status && error.status >= 400 && error.status < 500 && error.status !== 429) {
          break;
        }

        // Exponential backoff
        if (i < maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, 1000 * Math.pow(2, i)));
        }
      }
    }

    throw lastError;
  }
}

// ==================== Type Definitions ====================
export interface ApiConfig {
  baseURL: string;
  timeout: number;
  withCredentials: boolean;
}

// Export configuration for external use
export const apiConfig: ApiConfig = {
  baseURL: API_BASE_URL,
  timeout: 15000,
  withCredentials: true,
};

// Default export for convenience
export default ApiService;