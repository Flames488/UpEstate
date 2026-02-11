"use client";

import { api } from "@/services/api";

export default function BillingPortalButton() {
  async function openPortal() {
    const res = await api.post("/billing/portal");
    window.location.href = res.data.url;
  }

  return (
    <button
      onClick={openPortal}
      className="border px-4 py-2 rounded"
    >
      Manage Subscription
    </button>
  );
}
