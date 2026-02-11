"use client";

import { ReactNode, useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";
import { useAuth } from "../providers/AuthProvider";

export default function ProtectedRoute({
  children,
  role,
}: {
  children: ReactNode;
  role?: string;
}) {
  const { user, loading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (!loading) {
      if (!user) {
        router.replace(`/login?redirect=${pathname}`);
      } else if (role && user.role !== role) {
        router.replace("/403");
      }
    }
  }, [user, loading, role, router, pathname]);

  if (loading || !user) {
    return (
      <div style={{ padding: 50, textAlign: "center" }}>
        <h3>Loading...</h3>
      </div>
    );
  }

  return <>{children}</>;
}
