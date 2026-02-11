export default function PricingCard({ title, price, onSelect }: any) {
  return (
    <div className="card">
      <h3>{title}</h3>
      <p>{price}</p>
      <button onClick={onSelect}>Choose</button>
    </div>
  )
}
