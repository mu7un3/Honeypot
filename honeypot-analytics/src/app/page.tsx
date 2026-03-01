"use client"

import { useState, useEffect } from "react"
import dynamic from "next/dynamic"
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  AreaChart,
  Area,
} from "recharts"

const AttackMap = dynamic(() => import("@/components/AttackMap"), { ssr: false })
import {
  Shield,
  AlertTriangle,
  Globe,
  Server,
  Skull,
  Clock,
  Users,
  Activity,
  RefreshCw,
  Zap,
  Eye,
  Download,
  ChevronDown,
  ChevronUp,
  Brain,
  Flame,
  Bug,
  Lock,
} from "lucide-react"

// ── Types ──────────────────────────────────────────────────────────────────────

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

interface AttackLocation {
  ip: string
  lat: number
  lon: number
  country: string
  city: string
  service: string
  timestamp: string
  threat_score: number
  severity: string
}

interface Analytics {
  totalAttacks: number
  uniqueAttackers: number
  blockedIPs: number
  avgThreatScore: number
  criticalCount: number
  anomalyCount: number
  services: { name: string; count: number }[]
  countries: { name: string; count: number }[]
  attackTypes: { name: string; count: number }[]
  severities: { name: string; count: number }[]
  attackerProfiles: { name: string; count: number }[]
  timeline: { time: string; count: number }[]
  recentAttacks: AttackRow[]
  attackLocations: AttackLocation[]
  firstAttack: string
  lastAttack: string
}

// ── Colour palettes ────────────────────────────────────────────────────────────

const CHART_COLORS = [
  "#ef4444", "#f97316", "#eab308", "#22c55e",
  "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899",
]

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
  INFO:     "#71717a",
}

const SEVERITY_BG: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400",
  HIGH:     "bg-orange-500/20 text-orange-400",
  MEDIUM:   "bg-yellow-500/20 text-yellow-400",
  LOW:      "bg-green-500/20 text-green-400",
  INFO:     "bg-zinc-600/30 text-zinc-400",
}

// ── Small helpers ──────────────────────────────────────────────────────────────

function ThreatBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-zinc-600 text-xs">—</span>
  const pct = Math.min(100, (score / 10) * 100)
  const color =
    score >= 8 ? "bg-red-500" :
    score >= 6 ? "bg-orange-500" :
    score >= 4 ? "bg-yellow-500" : "bg-green-500"
  return (
    <div className="flex items-center gap-2 min-w-[80px]">
      <div className="flex-1 bg-zinc-700 rounded-full h-2">
        <div className={`h-2 rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono w-7 text-right">{score.toFixed(1)}</span>
    </div>
  )
}

function SeverityBadge({ severity }: { severity: string | null }) {
  if (!severity) return null
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEVERITY_BG[severity] || SEVERITY_BG.INFO}`}>
      {severity}
    </span>
  )
}

function StatCard({
  icon, label, value, sub,
}: {
  icon: React.ReactNode
  label: string
  value: string | number
  sub?: string
}) {
  return (
    <div className="bg-zinc-900 rounded-xl p-5 flex flex-col gap-2">
      <div className="flex items-center gap-2">
        {icon}
        <span className="text-zinc-400 text-sm">{label}</span>
      </div>
      <p className="text-3xl font-bold leading-none">{value}</p>
      {sub && <p className="text-xs text-zinc-500">{sub}</p>}
    </div>
  )
}

// ── Attack detail panel ────────────────────────────────────────────────────────

function AttackDetail({ attack, onClose }: { attack: AttackRow; onClose: () => void }) {
  return (
    <div
      className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4"
      onClick={onClose}
    >
      <div
        className="bg-zinc-900 rounded-xl p-6 max-w-xl w-full max-h-[80vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-bold text-lg font-mono">{attack.attacker_ip}</h3>
          <button onClick={onClose} className="text-zinc-500 hover:text-white text-xl leading-none">×</button>
        </div>

        <div className="grid grid-cols-2 gap-3 text-sm mb-4">
          <Row label="Service"   value={attack.service} />
          <Row label="Port"      value={attack.honeypot_port} />
          <Row label="Country"   value={`${attack.info.country}, ${attack.info.city}`} />
          <Row label="ISP"       value={attack.info.isp || "—"} />
          <Row label="ASN"       value={attack.info.asn || "—"} />
          <Row label="rDNS"      value={attack.info.reverse_dns || "—"} />
          <Row label="Hits"      value={attack.hit_count} />
          <Row label="Time"      value={attack.timestamp?.slice(0, 19)} />
        </div>

        <div className="border-t border-zinc-700 pt-4 space-y-3 text-sm">
          <div className="flex items-center gap-3">
            <span className="text-zinc-500 w-28 shrink-0">Threat Score</span>
            <ThreatBar score={attack.threat_score} />
          </div>
          <div className="flex items-center gap-3">
            <span className="text-zinc-500 w-28 shrink-0">Severity</span>
            <SeverityBadge severity={attack.severity} />
          </div>
          <div className="flex items-center gap-3">
            <span className="text-zinc-500 w-28 shrink-0">Attack Type</span>
            <span className="font-mono text-blue-400">{attack.attack_type || "—"}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-zinc-500 w-28 shrink-0">Attacker Profile</span>
            <span className="text-purple-400">{attack.profile || "—"}</span>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-zinc-500 w-28 shrink-0">Anomaly</span>
            {attack.is_anomaly
              ? <span className="text-red-400 font-semibold">YES — Unusual behaviour detected</span>
              : <span className="text-zinc-500">No</span>}
          </div>
          {attack.indicators?.length > 0 && (
            <div>
              <span className="text-zinc-500 block mb-1">Indicators</span>
              <div className="flex flex-wrap gap-1">
                {attack.indicators.map((ind, i) => (
                  <span key={i} className="px-2 py-0.5 bg-red-900/30 text-red-400 rounded text-xs">{ind}</span>
                ))}
              </div>
            </div>
          )}
          {attack.payload_decoded && (
            <div>
              <span className="text-zinc-500 block mb-1">Payload</span>
              <pre className="bg-zinc-800 rounded p-3 text-xs text-green-300 overflow-x-auto whitespace-pre-wrap break-all">
                {attack.payload_decoded.slice(0, 512)}
                {attack.payload_decoded.length > 512 && "\n… (truncated)"}
              </pre>
            </div>
          )}
          {attack.info.attack_signature && (
            <div>
              <span className="text-zinc-500 block mb-1">Signature</span>
              <span className="text-zinc-300 text-xs">{attack.info.attack_signature}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Row({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <p className="text-zinc-500 text-xs">{label}</p>
      <p className="font-mono text-sm break-all">{value}</p>
    </div>
  )
}

// ── Live feed table ────────────────────────────────────────────────────────────

function LiveFeed({ attacks }: { attacks: AttackRow[] }) {
  const [expanded, setExpanded] = useState(false)
  const [selected, setSelected] = useState<AttackRow | null>(null)

  const shown = expanded ? attacks : attacks.slice(0, 8)

  return (
    <div className="bg-zinc-900 rounded-xl p-6">
      <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Activity className="w-5 h-5 text-purple-500" />
        Live Attack Feed
        <span className="ml-auto text-xs text-zinc-500">{attacks.length} events</span>
      </h2>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-zinc-500 border-b border-zinc-700 text-xs">
              <th className="pb-2 pr-3">Time</th>
              <th className="pb-2 pr-3">Attacker</th>
              <th className="pb-2 pr-3">Service</th>
              <th className="pb-2 pr-3">Severity</th>
              <th className="pb-2 pr-3">Threat</th>
              <th className="pb-2 pr-3">Type</th>
              <th className="pb-2">Flags</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((attack, i) => (
              <tr
                key={i}
                className="border-b border-zinc-800 hover:bg-zinc-800/60 cursor-pointer"
                onClick={() => setSelected(attack)}
              >
                <td className="py-2 pr-3 font-mono text-zinc-400 text-xs whitespace-nowrap">
                  {attack.timestamp?.slice(11, 19)}
                </td>
                <td className="py-2 pr-3 font-mono text-xs">{attack.attacker_ip}</td>
                <td className="py-2 pr-3">
                  <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">{attack.service}</span>
                </td>
                <td className="py-2 pr-3">
                  <SeverityBadge severity={attack.severity} />
                </td>
                <td className="py-2 pr-3">
                  <ThreatBar score={attack.threat_score} />
                </td>
                <td className="py-2 pr-3 text-zinc-300 text-xs">{attack.attack_type || "—"}</td>
                <td className="py-2 flex gap-1 flex-wrap">
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

      {attacks.length > 8 && (
        <button
          onClick={() => setExpanded(e => !e)}
          className="mt-3 text-xs text-zinc-500 hover:text-white flex items-center gap-1 mx-auto"
        >
          {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          {expanded ? "Show less" : `Show all ${attacks.length} events`}
        </button>
      )}

      {selected && <AttackDetail attack={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function Home() {
  const [analytics, setAnalytics] = useState<Analytics | null>(null)
  const [loading, setLoading] = useState(true)
  const [exporting, setExporting] = useState(false)

  const fetchAnalytics = async () => {
    setLoading(true)
    try {
      const res = await fetch("/api/analytics")
      const data = await res.json()
      setAnalytics(data)
    } catch (err) {
      console.error("Failed to fetch analytics:", err)
    }
    setLoading(false)
  }

  const exportIOC = async () => {
    setExporting(true)
    try {
      const res = await fetch("/api/analytics", { method: "POST" })
      if (!res.ok) throw new Error("Export failed")
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = `ioc_export_${new Date().toISOString().slice(0, 10)}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error("IOC export error:", err)
    }
    setExporting(false)
  }

  useEffect(() => {
    fetchAnalytics()
    const interval = setInterval(fetchAnalytics, 5000)
    return () => clearInterval(interval)
  }, [])

  if (loading && !analytics) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-12 h-12 text-red-500 animate-spin mx-auto mb-4" />
          <p className="text-zinc-400">Loading honeypot data...</p>
        </div>
      </div>
    )
  }

  if (!analytics || analytics.totalAttacks === 0) {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center">
        <div className="text-center">
          <Shield className="w-16 h-16 text-green-500 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-2">No Attacks Detected</h1>
          <p className="text-zinc-400">Your honeypot is running. Attacks will appear here.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-white p-6">
      <div className="max-w-7xl mx-auto space-y-6">

        {/* ── Header ─────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-10 h-10 text-red-500" />
            <div>
              <h1 className="text-2xl font-bold">Honeypot Analytics</h1>
              <p className="text-zinc-400 text-sm">
                ML-Enhanced · Live · Last updated {analytics.lastAttack}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={exportIOC}
              disabled={exporting}
              className="flex items-center gap-2 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 rounded-lg transition text-sm"
            >
              <Download className={`w-4 h-4 ${exporting ? "animate-bounce" : ""}`} />
              Export IOC
            </button>
            <button
              onClick={fetchAnalytics}
              className="flex items-center gap-2 px-3 py-2 bg-zinc-800 hover:bg-zinc-700 rounded-lg transition text-sm"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>

        {/* ── 6 Stat cards ───────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <StatCard
            icon={<Skull className="w-5 h-5 text-red-500" />}
            label="Total Attacks"
            value={analytics.totalAttacks}
          />
          <StatCard
            icon={<Users className="w-5 h-5 text-orange-500" />}
            label="Unique Attackers"
            value={analytics.uniqueAttackers}
          />
          <StatCard
            icon={<Lock className="w-5 h-5 text-yellow-500" />}
            label="Blocked IPs"
            value={analytics.blockedIPs}
          />
          <StatCard
            icon={<Brain className="w-5 h-5 text-blue-500" />}
            label="Avg Threat Score"
            value={analytics.avgThreatScore.toFixed(1)}
            sub="out of 10"
          />
          <StatCard
            icon={<Flame className="w-5 h-5 text-red-600" />}
            label="Critical Hits"
            value={analytics.criticalCount}
          />
          <StatCard
            icon={<Bug className="w-5 h-5 text-purple-500" />}
            label="Anomalies"
            value={analytics.anomalyCount}
          />
        </div>

        {/* ── Timeline ───────────────────────────────────────────────── */}
        {analytics.timeline.length > 0 && (
          <div className="bg-zinc-900 rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Clock className="w-5 h-5 text-cyan-500" />
              Attack Timeline (last 24 h — 10-min buckets)
            </h2>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={analytics.timeline}>
                  <defs>
                    <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#ef4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0}   />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                  <XAxis
                    dataKey="time"
                    stroke="#71717a"
                    tick={{ fontSize: 10 }}
                    tickFormatter={v => v.slice(11, 16)}
                  />
                  <YAxis stroke="#71717a" tick={{ fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", fontSize: 12 }}
                    labelStyle={{ color: "#fff" }}
                    formatter={(v: number) => [v, "attacks"]}
                    labelFormatter={v => `${v} UTC`}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    stroke="#ef4444"
                    strokeWidth={2}
                    fill="url(#grad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {/* ── Charts row 1 ───────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Severity distribution */}
          <div className="bg-zinc-900 rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-yellow-500" />
              Severity Breakdown
            </h2>
            <div className="space-y-2">
              {["CRITICAL","HIGH","MEDIUM","LOW","INFO"].map(sev => {
                const entry = analytics.severities.find(s => s.name === sev)
                const count = entry?.count || 0
                const max   = Math.max(...analytics.severities.map(s => s.count), 1)
                return (
                  <div key={sev} className="flex items-center gap-3 text-sm">
                    <span className="w-16 text-xs text-zinc-400">{sev}</span>
                    <div className="flex-1 bg-zinc-800 rounded-full h-3">
                      <div
                        className="h-3 rounded-full transition-all"
                        style={{
                          width: `${(count / max) * 100}%`,
                          backgroundColor: SEVERITY_COLOR[sev] || "#71717a",
                        }}
                      />
                    </div>
                    <span className="w-8 text-right font-mono text-xs">{count}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* ML Attack Classification */}
          <div className="bg-zinc-900 rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Brain className="w-5 h-5 text-blue-500" />
              ML Attack Classification
            </h2>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={analytics.attackTypes} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                  <XAxis type="number" stroke="#71717a" tick={{ fontSize: 10 }} />
                  <YAxis dataKey="name" type="category" width={90} stroke="#71717a" tick={{ fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", fontSize: 12 }}
                    labelStyle={{ color: "#fff" }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Attacker Profiles donut */}
          <div className="bg-zinc-900 rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Eye className="w-5 h-5 text-purple-500" />
              Attacker Profiles
              <span className="text-xs text-zinc-500 ml-1">(K-Means)</span>
            </h2>
            {analytics.attackerProfiles.length > 0 ? (
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={analytics.attackerProfiles}
                      dataKey="count"
                      nameKey="name"
                      cx="50%"
                      cy="50%"
                      innerRadius={40}
                      outerRadius={70}
                      label={({ name, percent }) =>
                        percent > 0.06 ? `${name.split(" ")[0]} ${(percent * 100).toFixed(0)}%` : ""
                      }
                      labelLine={false}
                    >
                      {analytics.attackerProfiles.map((_, i) => (
                        <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", fontSize: 12 }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="h-48 flex items-center justify-center text-zinc-600 text-sm">
                No ML profile data yet
              </div>
            )}
          </div>
        </div>

        {/* ── Charts row 2 ───────────────────────────────────────────── */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

          {/* Top services */}
          <div className="bg-zinc-900 rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Server className="w-5 h-5 text-blue-500" />
              Top Attacked Services
            </h2>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={analytics.services} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                  <XAxis type="number" stroke="#71717a" tick={{ fontSize: 10 }} />
                  <YAxis dataKey="name" type="category" width={80} stroke="#71717a" tick={{ fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", fontSize: 12 }}
                    labelStyle={{ color: "#fff" }}
                  />
                  <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Countries */}
          <div className="bg-zinc-900 rounded-xl p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
              <Globe className="w-5 h-5 text-green-500" />
              Attack Sources by Country
            </h2>
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={analytics.countries}
                    dataKey="count"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={85}
                    label={({ name, percent }) =>
                      percent > 0.04 ? `${name} ${(percent * 100).toFixed(0)}%` : ""
                    }
                    labelLine={false}
                  >
                    {analytics.countries.map((_, i) => (
                      <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", fontSize: 12 }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>

        {/* ── Attack Map ─────────────────────────────────────────────── */}
        <AttackMap attacks={analytics.attackLocations || []} />

        {/* ── Live feed ──────────────────────────────────────────────── */}
        <LiveFeed attacks={analytics.recentAttacks} />

        {/* ── Footer ─────────────────────────────────────────────────── */}
        <div className="text-center text-zinc-600 text-xs pb-4">
          <Zap className="inline w-3 h-3 mr-1" />
          Auto-refreshes every 5 seconds · First attack: {analytics.firstAttack}
        </div>

      </div>
    </div>
  )
}
