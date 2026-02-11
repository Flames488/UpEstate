import { requireUser } from "@/lib/auth-server";
import ProtectedRoute from "../components/ProtectedRoute";

export default async function AdminLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const user = await requireUser();

  if (!user.roles?.includes("admin")) {
    throw new Error("Forbidden");
  }

  return <ProtectedRoute role="admin">{children}</ProtectedRoute>;
}
