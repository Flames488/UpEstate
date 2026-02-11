"use client";

import { useEffect, useState } from "react";
import { api } from "@/services/api";

export default function PlansPage() {
  const [plans, setPlans] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.get("/billing/plans").then(res => setPlans(res.data));
  }, []);

  async function subscribe(planId: string) {
    setLoading(true);

    const res = await api.post("/billing/subscribe", {
      plan_id: planId,
    });

    window.location.href = res.data.checkout_url;
  }

  return (
    <div className="max-w-6xl mx-auto py-12">
      <h1 className="text-4xl font-bold mb-8">Choose a Plan</h1>

      <div className="grid grid-cols-3 gap-6">
        {plans.map(p => (
          <div
            key={p.id}
            className="border rounded-xl p-6 shadow hover:scale-105 transition"
          >
            <h2 className="text-2xl font-semibold">{p.name}</h2>
            <p className="text-3xl mt-4">${p.price}/mo</p>

            <ul className="mt-6 space-y-2 text-gray-600">
              {p.features.map((f: string) => (
                <li key={f}>✔ {f}</li>
              ))}
            </ul>

            <button
              onClick={() => subscribe(p.id)}
              disabled={loading}
              className="mt-6 w-full bg-black text-white py-3 rounded-lg"
            >
              Subscribe
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
