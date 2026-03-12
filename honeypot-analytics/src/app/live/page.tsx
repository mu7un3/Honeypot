"use client"

import { useState, useEffect } from "react"
import { Activity, RefreshCw, Shield, AlertTriangle } from "lucide-react"

interface AttackRow {
  attacker_ip: string
  attacker_port: number
  honeypot_port: number
  service: string
  timestamp: string
  hit_count: number
  payload_decoded: string
  threat_score: number | null
  severity: string | null
  attack_type: string | null
  is_anomaly: boolean
  profile: string | null
  indicators: string[]
  info: {
    country: string
    city: string
    isp: string
    asn: string
    attack_signature: string
    reverse_dns: string
    lat: number
    lon: number
  }
}

const SEVERITY_BG: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400",
  HIGH: "bg-orange-500/20 text-orange-400",
  MEDIUM: "bg-yellow-500/20 text-yellow-400",
  LOW: "bg-green-500/20 text-green-400",
  INFO: "bg-zinc-600/30 text-zinc-400",
}

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return null
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_BG[severity] || SEVERITY_BG.INFO}`}>
      {severity}
    </span>
  )
}

function ThreatBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-zinc-600 text-xs">—</span>
  const pct = Math.min(100, (score / 10) * 100)
  const color = score >= 8 ? "bg-red-500" : score >= 6 ? "bg-orange-500" : score >= 4 ? "bg-yellow-500" : "bg-green-500"
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="flex-1 bg-zinc-700 rounded-full h-2">
        <div className={`h-2 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono w-7 text-right">{score.toFixed(1)}</span>
    </div>
  )
}

export default function LiveFeedPage() {
  const [attacks, setAttacks] = useState<AttackRow[]>([])
  const [loading, setLoading] = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(true)

  const fetchAttacks = async () => {
    try {
      const res = await fetch("/api/analytics")
      const data = await res.json()
      setAttacks(data.recentAttacks || [])
    } catch (err) {
      console.error("Failed to fetch attacks:", err)
    }
    setLoading(false)
  }

  useEffect(() => {
    fetchAttacks()
    if (!autoRefresh) return
    const interval = setInterval(fetchAttacks, 3000)
    return () => clearInterval(interval)
  }, [autoRefresh])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Live Attack Feed</h1>
          <p className="text-zinc-400 text-sm mt-1">Real-time intrusion detection events</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
              autoRefresh ? "bg-green-500/20 text-green-400" : "bg-zinc-800 text-zinc-400"
            }`}
          >
            Auto-refresh: {autoRefresh ? "ON" : "OFF"}
          </button>
          <button
            onClick={fetchAttacks}
            className="flex items-center gap-2 px-4 py-2 bg-red-500 hover:bg-red-600 rounded-lg transition text-sm font-medium"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-5 h-5 text-red-500" />
            <span className="text-zinc-400 text-sm">Total Events</span>
          </div>
          <p className="text-3xl font-bold">{attacks.length}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-5 h-5 text-orange-500" />
            <span className="text-zinc-400 text-sm">Unique Attackers</span>
          </div>
          <p className="text-3xl font-bold">{new Set(attacks.map(a => a.attacker_ip)).size}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-5 h-5 text-red-600" />
            <span className="text-zinc-400 text-sm">Critical</span>
          </div>
          <p className="text-3xl font-bold">{attacks.filter(a => a.severity === "CRITICAL").length}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-5 h-5 text-purple-500" />
            <span className="text-zinc-400 text-sm">Anomalies</span>
          </div>
          <p className="text-3xl font-bold">{attacks.filter(a => a.is_anomaly).length}</p>
        </div>
      </div>

      {/* Live Feed Table */}
      <div className="bg-zinc-900 rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Activity className="w-5 h-5 text-purple-500" />
          Attack Events
          <span className="ml-auto text-xs text-zinc-500">{attacks.length} events</span>
        </h2>

        {attacks.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="w-16 h-16 text-green-500 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">No Attacks Detected</h3>
            <p className="text-zinc-400 text-sm">Your honeypot is actively monitoring. Attacks will appear here in real-time.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-zinc-500 border-b border-zinc-700 text-xs">
                  <th className="pb-3 pr-3">Time</th>
                  <th className="pb-3 pr-3">Attacker</th>
                  <th className="pb-3 pr-3">Service</th>
                  <th className="pb-3 pr-3">Location</th>
                  <th className="pb-3 pr-3">Severity</th>
                  <th className="pb-3 pr-3">Threat</th>
                  <th className="pb-3 pr-3">Type</th>
                  <th className="pb-3">Flags</th>
                </tr>
              </thead>
              <tbody>
                {attacks.map((attack, i) => (
                  <tr key={i} className="border-b border-zinc-800 hover:bg-zinc-800/60">
                    <td className="py-3 pr-3 font-mono text-zinc-400 text-xs whitespace-nowrap">
                      {attack.timestamp?.slice(11, 19)}
                    </td>
                    <td className="py-3 pr-3 font-mono text-xs">{attack.attacker_ip}</td>
                    <td className="py-3 pr-3">
                      <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">{attack.service}</span>
                    </td>
                    <td className="py-3 pr-3 text-xs text-zinc-400">
                      {attack.info.city}, {attack.info.country}
                    </td>
                    <td className="py-3 pr-3">
                      <SeverityBadge severity={attack.severity} />
                    </td>
                    <td className="py-3 pr-3">
                      <ThreatBar score={attack.threat_score} />
                    </td>
                    <td className="py-3 pr-3 text-zinc-300 text-xs">{attack.attack_type || "—"}</td>
                    <td className="py-3 flex gap-1 flex-wrap">
                      {attack.is_anomaly && (
                        <span title="Anomaly detected" className="text-red-400 text-xs font-bold">⚠</span>
                      )}
                      {(attack.hit_count ?? 1) > 4 && (
                        <span title="Repeat offender" className="text-orange-400 text-xs font-bold">↻</span>
                      )}
                      {attack.indicators?.length > 0 && (
                        <span title={attack.indicators.join(", ")} className="text-yellow-400 text-xs font-bold">!</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
