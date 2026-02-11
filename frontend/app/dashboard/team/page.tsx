"use client";

import { useEffect, useState } from "react";
import { api } from "@/services/api";

export default function Team() {
  const [members, setMembers] = useState([]);

  useEffect(() => {
    api.get("/team").then(r => setMembers(r.data));
  }, []);

  return (
    <div>
      <h1 className="text-2xl mb-6">Team Members</h1>

      {members.map((m: any) => (
        <div key={m.id}>
          {m.email} — {m.role}
        </div>
      ))}
    </div>
  );
}
