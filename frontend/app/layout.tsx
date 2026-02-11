import { AuthProvider } from "./providers/AuthProvider";


// Put this at the very top of the file
if (!process.env.NEXT_PUBLIC_API_URL) {
  throw new Error("NEXT_PUBLIC_API_URL is missing");
}

import './globals.css'

export const metadata = {
  title: 'SaaS App',
  description: 'Secure SaaS platform'
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
  <AuthProvider>
    {children}
  </AuthProvider>
</body>
    </html>
  )
}