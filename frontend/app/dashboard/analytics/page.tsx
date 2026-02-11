"use client";

import { useEffect, useState } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  ResponsiveContainer,
} from "recharts";
import { api } from "@/services/api";

export default function Analytics() {
  const [data, setData] = useState<any[]>([]);

  useEffect(() => {
    api
      .get("/billing/admin/analytics")
      .then(r => setData(r.data.revenue));
  }, []);

  return (
    <div>
      <h1 className="text-3xl font-bold mb-8">
        Revenue Analytics
      </h1>

      <div className="bg-white p-6 rounded-xl shadow">
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={data}>
            <XAxis dataKey="date" />
            <YAxis />
            <Tooltip />
            <CartesianGrid strokeDasharray="3 3" />
            <Line dataKey="amount" />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
