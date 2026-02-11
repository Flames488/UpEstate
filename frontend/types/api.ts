// frontend/types/api.ts
export interface ApiResponse<T = any> {
  data: T;
  status: number;
  success: boolean;
  message?: string;
}

export interface ApiError {
  message: string;
  status: number;
  data?: any;
  errors?: Record<string, string[]>;
}

export interface PaginatedResponse<T = any> {
  data: T[];
  meta: {
    current_page: number;
    last_page: number;
    per_page: number;
    total: number;
    from: number;
    to: number;
  };
  links: {
    first: string;
    last: string;
    prev: string | null;
    next: string | null;
  };
}