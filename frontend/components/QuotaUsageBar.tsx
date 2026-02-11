
export function QuotaUsageBar({ used, limit }: { used: number; limit: number }) {
  const percent = Math.min(100, (used / limit) * 100)
  return (
    <div className="space-y-1">
      <div className="text-sm">{used} / {limit} automations</div>
      <div className="h-2 bg-gray-200 rounded">
        <div className="h-2 bg-blue-600 rounded" style={{ width: `${percent}%` }} />
      </div>
    </div>
  )
}
