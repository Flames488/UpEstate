"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  ReactNode,
} from "react";
import { api } from "@/services/api";

interface AuthContextType {
  user: any;
  loading: boolean;
  logout: () => void;
  reloadUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

const TOKEN_KEY = "access_token";

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  async function loadSession() {
    const token = localStorage.getItem(TOKEN_KEY);

    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }

    try {
      // Attach token to API client
      api.defaults.headers.common["Authorization"] = `Bearer ${token}`;

      const res = await api.get("/auth/me");
      setUser(res.data);
    } catch (err) {
      // Token invalid or expired
      localStorage.removeItem(TOKEN_KEY);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }

  function logout() {
    localStorage.removeItem(TOKEN_KEY);
    delete api.defaults.headers.common["Authorization"];
    setUser(null);
    window.location.href = "/login";
  }

  useEffect(() => {
    loadSession();
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        logout,
        reloadUser: loadSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return ctx;
}
