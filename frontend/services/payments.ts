import { api } from "./api";

export async function verifyPaystack(reference: string) {
  const res = await api.post("/billing/paystack/verify", {
    reference,
  });

  return res.data;
}
