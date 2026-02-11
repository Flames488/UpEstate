
import { cookies } from "next/headers"
import jwt from "jsonwebtoken"

export function requireUser() {
  const token = cookies().get("access_token")?.value
  if (!token) throw new Error("Unauthorized")
  return jwt.verify(token, process.env.JWT_SECRET!)
}
