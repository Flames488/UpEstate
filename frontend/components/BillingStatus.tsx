import { useEffect, useState } from "react";
import { api } from "@/services/api";

export default function BillingStatus() {
  const [sub, setSub] = useState<any>(null);

  useEffect(() => {
    api.get("/billing/me").then(r => setSub(r.data));
  }, []);

  if (!sub) return null;

  return (
    <div className="bg-white rounded-xl shadow p-6">
      <h3 className="text-xl font-semibold mb-3">Subscription</h3>

      <p>Status: <b>{sub.status}</b></p>
      <p>Plan: {sub.plan_name}</p>
      <p>Renews: {sub.current_period_end}</p>

      <a
        href="/billing/plans"
        className="inline-block mt-4 underline"
      >
        Change Plan
      </a>
    </div>
  );
}
