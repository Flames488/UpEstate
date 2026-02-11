export function handleApiError(err: any) {
  if (err.response?.status === 429) {
    alert("Too many requests. Please slow down.");
  }
}
