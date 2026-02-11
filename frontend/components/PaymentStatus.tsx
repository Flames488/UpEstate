export default function PaymentStatus({ status }: { status: string }) {
  return <div className={`status ${status}`}>Payment {status}</div>
}
