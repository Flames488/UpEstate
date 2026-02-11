"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

interface HealthProviderProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export default function HealthProvider({ 
  children, 
  fallback = <div>Checking service availability...</div> 
}: HealthProviderProps) {
  const [status, setStatus] = useState<"loading" | "healthy" | "unhealthy">("loading");

  useEffect(() => {
    let isMounted = true;
    
    const checkHealth = async () => {
      try {
        // Add timeout to prevent hanging
        const timeout = new Promise((_, reject) => 
          setTimeout(() => reject(new Error("Timeout")), 5000)
        );
        
        await Promise.race([api.get("/api/v1/health"), timeout]);
        
        if (isMounted) {
          setStatus("healthy");
        }
      } catch (error) {
        console.warn("Health check failed:", error);
        
        if (isMounted) {
          setStatus("unhealthy");
        }
      }
    };

    checkHealth();
    
    // Optional: Polling for ongoing health checks
    const interval = setInterval(checkHealth, 30000);
    
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  if (status === "loading") {
    return <>{fallback}</>;
  }

  if (status === "unhealthy") {
    return (
      <div style={styles.errorContainer}>
        <div style={styles.errorContent}>
          <h1>Service Temporarily Unavailable</h1>
          <p>We're experiencing technical difficulties. Please try again in a few moments.</p>
          <button 
            onClick={() => {
              setStatus("loading");
              window.location.reload();
            }}
            style={styles.retryButton}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}

const styles = {
  errorContainer: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "100vh",
    backgroundColor: "#f5f5f5",
    padding: "20px",
  },
  errorContent: {
    textAlign: "center" as const,
    maxWidth: "500px",
    padding: "40px",
    backgroundColor: "white",
    borderRadius: "8px",
    boxShadow: "0 2px 10px rgba(0,0,0,0.1)",
  },
  retryButton: {
    marginTop: "20px",
    padding: "10px 20px",
    backgroundColor: "#0070f3",
    color: "white",
    border: "none",
    borderRadius: "4px",
    cursor: "pointer",
  },
};