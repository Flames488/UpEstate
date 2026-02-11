import { ReactNode } from "react"
import { useAuth } from "@/hooks/useAuth"

export default function AdminGuard({ children }: { children: ReactNode }) {
  const { user } = useAuth()

  if (!user || user.role !== "admin") {
    return null
  }

  return <>{children}</>
}
