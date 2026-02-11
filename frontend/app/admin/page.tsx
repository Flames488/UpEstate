'use client'
import RouteGuard from '../../components/RouteGuard'

export default function Admin() {
  return (
    <RouteGuard role="admin">
      <h2>Admin Panel</h2>
    </RouteGuard>
  )
}
