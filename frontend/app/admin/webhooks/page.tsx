"use client";

import { useEffect, useState } from "react";
import { api } from "@/services/api";

export default function WebhookDashboard() {
  const [hooks, setHooks] = useState<any[]>([]);

  useEffect(() => {
    api.get("/billing/admin/webhooks").then(r => {
      setHooks(r.data);
    });
  }, []);

  async function retry(id: string) {
    await api.post(`/billing/admin/retry-webhook/${id}`);
    alert("Retry triggered");
  }

  return (
    <div className="max-w-6xl mx-auto py-12">
      <h1 className="text-3xl font-bold mb-6">Webhook Fail proving</h1>

      <table className="w-full border">
        <thead>
          <tr>
            <th>ID</th>
            <th>Event</th>
            <th>Status</th>
            <th>Error</th>
            <th></th>
          </tr>
        </thead>

        <tbody>
          {hooks.map(h => (
            <tr key={h.id}>
              <td>{h.id}</td>
              <td>{h.event}</td>
              <td>{h.status}</td>
              <td className="text-red-600">{h.last_error}</td>

              <td>
                <button
                  onClick={() => retry(h.id)}
                  className="underline"
                >
                  Retry
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
