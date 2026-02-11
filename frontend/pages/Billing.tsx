import PricingCard from '../components/PricingCard'
import PaymentStatus from '../components/PaymentStatus'

export default function Billing() {
  return (
    <div>
      <h2>Billing</h2>
      <PricingCard title="Pro" price="$10/mo" onSelect={() => {}} />
      <PaymentStatus status="pending" />
    </div>
  )
}
