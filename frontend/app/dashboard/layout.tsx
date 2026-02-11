
import { requireUser } from "@/lib/auth-server"

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  requireUser()
  return <>{children}</>
}
