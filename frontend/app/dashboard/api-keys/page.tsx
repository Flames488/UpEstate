"use client";

import { useEffect, useState } from "react";
import { api } from "@/services/api";

export default function ApiKeys() {
  const [keys, setKeys] = useState<any[]>([]);

  useEffect(() => {
    api.get("/keys").then(r => setKeys(r.data));
  }, []);

  return (
    <div>
      <h1 className="text-2xl mb-6">API Keys</h1>

      {keys.map(k => (
        <div key={k.id}>
          {k.name} – ****{k.last4}
        </div>
      ))}
    </div>
  );
}
