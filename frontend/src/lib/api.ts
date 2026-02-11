
import axios from "axios";

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
  withCredentials: true,
  timeout: 10000,
});

api.interceptors.response.use(
  res => res,
  async err => {
    if (err.response?.status === 401) {
      try {
        await api.post("/auth/refresh");
        return api(err.config);
      } catch {
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  }
);
