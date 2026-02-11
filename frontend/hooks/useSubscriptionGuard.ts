import { useEffect } from "react";
import { api } from "@/lib/api";

export function useSubscriptionGuard() {
  useEffect(() => {
    api.get("/api/v1/billing/status")
      .catch(err => {
        if (err.response?.status === 402) {
          window.location.href = "/billing/upgrade";
        }
      });
  }, []);
}
