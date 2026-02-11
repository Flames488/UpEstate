import { Link } from 'react-router-dom'
import TrustBanner from '../components/TrustBanner'

export default function Landing() {
  return (
    <div>
      <h1>Welcome</h1>
      <TrustBanner />
      <Link to="/onboarding">Get Started</Link>
    </div>
  )
}
