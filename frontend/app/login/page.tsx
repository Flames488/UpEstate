"use client";

import { useState, useEffect } from "react";
import { api } from "@/services/api";
import { useAuth } from "../providers/AuthProvider";

export default function Login() {
  const { reloadUser } = useAuth();

  const [step, setStep] = useState<"login" | "otp">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [error, setError] = useState("");
  const [cooldown, setCooldown] = useState(0);

  const handleLogin = async () => {
    setError("");
    try {
      const res = await api.post("/login", { email, password });

      if (res.data.success) {
        setStep("otp");
        setCooldown(60);
      } else {
        setError(res.data.error || "Login failed");
      }
    } catch {
      setError("Server error");
    }
  };

  const handleVerifyOtp = async () => {
    setError("");
    try {
      const res = await api.post("/verify-otp", { email, otp });

      if (res.data.success) {
        localStorage.setItem("access_token", res.data.token);
        await reloadUser();

        const params = new URLSearchParams(window.location.search);
        const redirect = params.get("redirect") || "/";
        window.location.href = redirect;
      } else {
        setError(res.data.error || "Invalid OTP");
      }
    } catch {
      setError("Server error");
    }
  };

  const handleResend = async () => {
    setError("");
    try {
      const res = await api.post("/resend-otp", { email });
      if (res.data.success) {
        setCooldown(60);
      } else {
        setError(res.data.error || "Failed to resend OTP");
      }
    } catch {
      setError("Server error");
    }
  };

  useEffect(() => {
    if (cooldown <= 0) return;

    const timer = setInterval(() => {
      setCooldown((c) => c - 1);
    }, 1000);

    return () => clearInterval(timer);
  }, [cooldown]);

  return (
    <div style={{ maxWidth: 400, margin: "auto", marginTop: 100 }}>
      <h2>{step === "login" ? "Login" : "Enter OTP"}</h2>

      {error && <p style={{ color: "red" }}>{error}</p>}

      {step === "login" && (
        <>
          <input
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <br />
          <input
            placeholder="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <br />
          <button onClick={handleLogin}>Login</button>
        </>
      )}

      {step === "otp" && (
        <>
          <p>OTP sent to {email}</p>

          <input
            placeholder="Enter OTP"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
          />
          <br />

          <button onClick={handleVerifyOtp}>Verify OTP</button>

          <br />
          <br />

          <button onClick={handleResend} disabled={cooldown > 0}>
            {cooldown > 0
              ? `Resend OTP in ${cooldown}s`
              : "Resend OTP"}
          </button>
        </>
      )}
    </div>
  );
}
