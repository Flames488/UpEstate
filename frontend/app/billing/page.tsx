"use client";

import { useEffect } from "react";
import { verifyPaystack } from "@/services/paystack";
import { useSearchParams } from "next/navigation";

export default function BillingPage() {
  const params = useSearchParams();
  const ref = params.get("reference");

  useEffect(() => {
    if (ref) {
      verifyPaystack(ref)
        .then(() => location.href = "/dashboard")
        .catch(() => alert("Payment verification failed"));
    }
  }, [ref]);

  return <h1>Billing</h1>;
}
