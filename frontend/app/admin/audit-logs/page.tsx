"use client";

import { useEffect, useState } from "react";
import { api } from "@/services/api";

export default function AuditLogs() {
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    api.get("/admin/audit-logs").then(r => setLogs(r.data));
  }, []);

  return (
    <table>
      {logs.map((l: any) => (
        <tr key={l.id}>
          <td>{l.action}</td>
          <td>{l.user_email}</td>
          <td>{l.created_at}</td>
        </tr>
      ))}
    </table>
  );
}
