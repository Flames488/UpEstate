import { api } from "./api";

let isRefreshing = false;

api.interceptors.response.use(
  res => res,
  async error => {
    if (error.response?.status === 401 && !isRefreshing) {
      isRefreshing = true;
      try {
        await api.post("/api/v1/auth/refresh");
        isRefreshing = false;
        return api(error.config);
      } catch {
        window.location.href = "/login?expired=true";
      }
    }
    return Promise.reject(error);
  }
);
