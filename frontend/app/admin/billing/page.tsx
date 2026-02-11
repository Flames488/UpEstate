"use client";

import { useEffect, useState } from "react";
import { api } from "@/services/api";

export default function AdminBilling() {
  const [subs, setSubs] = useState<any[]>([]);

  useEffect(() => {
    api.get("/billing/admin/subscriptions").then(r => {
      setSubs(r.data);
    });
  }, []);

  return (
    <div className="max-w-7xl mx-auto py-12">
      <h1 className="text-4xl font-bold mb-8">Billing Admin</h1>

      <table className="w-full border">
        <thead>
          <tr className="bg-gray-100">
            <th>User</th>
            <th>Plan</th>
            <th>Status</th>
            <th>Provider</th>
            <th>Renews</th>
          </tr>
        </thead>

        <tbody>
          {subs.map(s => (
            <tr key={s.id} className="border-t">
              <td>{s.user_email}</td>
              <td>{s.plan}</td>
              <td>{s.status}</td>
              <td>{s.provider}</td>
              <td>{s.current_period_end}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
