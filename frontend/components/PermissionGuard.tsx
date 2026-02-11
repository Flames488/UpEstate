import { ReactNode } from "react"
import { useAuth } from "@/hooks/useAuth"

type Props = {
  allow: string[]
  children: ReactNode
}

export default function PermissionGuard({ allow, children }: Props) {
  const { user, loading } = useAuth()

  if (loading) return null

  if (!user) return null

  const hasPermission = allow.some(p =>
    user.permissions.includes(p)
  )

  if (!hasPermission) return null

  return <>{children}</>
}
