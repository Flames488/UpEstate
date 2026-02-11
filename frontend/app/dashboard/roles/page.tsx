"use client";

import { useEffect, useState } from "react";
import { api } from "@/services/api";

export default function Roles() {
  const [roles, setRoles] = useState([]);

  useEffect(() => {
    api.get("/roles").then(r => setRoles(r.data));
  }, []);

  return (
    <div>
      <h1 className="text-2xl mb-6">Roles</h1>

      {roles.map((r: any) => (
        <div key={r.id}>
          {r.name}
        </div>
      ))}
    </div>
  );
}
