"use client";

import { useEffect, useState } from "react";
import { api } from "@/services/api";

export default function Features() {
  const [flags, setFlags] = useState([]);

  useEffect(() => {
    api.get("/admin/features").then(r => setFlags(r.data));
  }, []);

  return (
    <div>
      {flags.map((f: any) => (
        <div key={f.id}>
          {f.name}: {String(f.enabled)}
        </div>
      ))}
    </div>
  );
}
