import { Routes, Route } from 'react-router-dom'
import Landing from '../pages/Landing'
import Onboarding from '../pages/Onboarding'
import Billing from '../pages/Billing'
import Dashboard from '../pages/Dashboard'

export default function Router() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/onboarding" element={<Onboarding />} />
      <Route path="/billing" element={<Billing />} />
      <Route path="/dashboard" element={<Dashboard />} />
    </Routes>
  )
}
