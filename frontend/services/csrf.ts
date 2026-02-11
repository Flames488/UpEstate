let csrfToken: string | null = null

export async function loadCsrfToken() {
  const res = await fetch(
    `${import.meta.env.VITE_API_URL}/auth/csrf-token`,
    { credentials: "include" }
  )
  const data = await res.json()
  csrfToken = data.csrfToken
}

export function getCsrfHeader() {
  return csrfToken ? { "X-CSRF-TOKEN": csrfToken } : {}
}