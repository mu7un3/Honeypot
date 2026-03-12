"use client"

import { useState, useEffect } from "react"
import { Brain, RefreshCw, Activity, Target } from "lucide-react"
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
} from "recharts"

interface Analytics {
  attackTypes: { name: string; count: number }[]
  severities: { name: string; count: number }[]
  attackerProfiles: { name: string; count: number }[]
  avgThreatScore: number
  anomalyCount: number
  criticalCount: number
}

const CHART_COLORS = [
  "#ef4444", "#f97316", "#eab308", "#22c55e",
  "#06b6d4", "#3b82f6", "#8b5cf6", "#ec4899",
]

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#22c55e",
  INFO: "#71717a",
}

export default function AnalysisPage() {
  const [analytics, setAnalytics] = useState<Analytics | null>(null)
  const [loading, setLoading] = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(true)

  const fetchAnalytics = async () => {
    try {
      const res = await fetch("/api/analytics")
      const data = await res.json()
      setAnalytics(data)
    } catch (err) {
      console.error("Failed to fetch analytics:", err)
    }
    setLoading(false)
  }

  useEffect(() => {
    fetchAnalytics()
    if (!autoRefresh) return
    const interval = setInterval(fetchAnalytics, 5000)
    return () => clearInterval(interval)
  }, [autoRefresh])

  if (!analytics) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <Brain className="w-12 h-12 text-blue-500 animate-pulse mx-auto mb-4" />
          <p className="text-zinc-400">Loading ML analysis...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">ML Analysis Dashboard</h1>
          <p className="text-zinc-400 text-sm mt-1">Machine learning attack classification and profiling</p>
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
            onClick={fetchAnalytics}
            className="flex items-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg transition text-sm font-medium"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* ML Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Brain className="w-5 h-5 text-blue-500" />
            <span className="text-zinc-400 text-sm">Avg Threat Score</span>
          </div>
          <p className="text-3xl font-bold">{analytics.avgThreatScore.toFixed(1)}<span className="text-lg text-zinc-500">/10</span></p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-5 h-5 text-purple-500" />
            <span className="text-zinc-400 text-sm">Anomalies</span>
          </div>
          <p className="text-3xl font-bold">{analytics.anomalyCount}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Target className="w-5 h-5 text-red-600" />
            <span className="text-zinc-400 text-sm">Critical Hits</span>
          </div>
          <p className="text-3xl font-bold">{analytics.criticalCount}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Brain className="w-5 h-5 text-green-500" />
            <span className="text-zinc-400 text-sm">Attack Types</span>
          </div>
          <p className="text-3xl font-bold">{analytics.attackTypes.length}</p>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ML Attack Classification */}
        <div className="bg-zinc-900 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Brain className="w-5 h-5 text-blue-500" />
            ML Attack Classification
          </h2>
          {analytics.attackTypes.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={analytics.attackTypes}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#3f3f46" />
                  <XAxis dataKey="name" stroke="#71717a" tick={{ fontSize: 10 }} angle={-45} textAnchor="end" height={80} />
                  <YAxis stroke="#71717a" tick={{ fontSize: 10 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", fontSize: 12 }}
                    labelStyle={{ color: "#fff" }}
                  />
                  <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-zinc-600 text-sm">
              No ML classification data yet
            </div>
          )}
        </div>

        {/* Severity Distribution */}
        <div className="bg-zinc-900 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <Activity className="w-5 h-5 text-yellow-500" />
            Severity Distribution
          </h2>
          {analytics.severities.length > 0 ? (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={analytics.severities}
                    dataKey="count"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    label={({ name, percent }) => `${name} ${((percent ?? 0) * 100).toFixed(0)}%`}
                    labelLine={false}
                  >
                    {analytics.severities.map((_, i) => (
                      <Cell key={i} fill={SEVERITY_COLOR[analytics.severities[i].name] || "#71717a"} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", fontSize: 12 }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center text-zinc-600 text-sm">
              No severity data yet
            </div>
          )}
        </div>
      </div>

      {/* Attacker Profiles */}
      <div className="bg-zinc-900 rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Target className="w-5 h-5 text-purple-500" />
          Attacker Profiles (K-Means Clustering)
        </h2>
        {analytics.attackerProfiles.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="h-64">
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
                    label={({ name, percent }) => (percent ?? 0) > 0.1 ? `${(name ?? "").split(" ")[0]} ${((percent ?? 0) * 100).toFixed(0)}%` : ""}
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
            <div className="space-y-3">
              {analytics.attackerProfiles.map((profile, i) => (
                <div key={i} className="flex items-center gap-3">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: CHART_COLORS[i % CHART_COLORS.length] }} />
                  <div className="flex-1">
                    <p className="text-sm font-medium text-white">{profile.name}</p>
                    <div className="w-full bg-zinc-800 rounded-full h-2 mt-1">
                      <div
                        className="h-2 rounded-full"
                        style={{
                          width: `${(profile.count / analytics.attackerProfiles.reduce((a, b) => a + b.count, 0)) * 100}%`,
                          backgroundColor: CHART_COLORS[i % CHART_COLORS.length],
                        }}
                      />
                    </div>
                  </div>
                  <span className="text-xs font-mono text-zinc-400 w-12 text-right">{profile.count}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="h-48 flex items-center justify-center text-zinc-600 text-sm">
            No attacker profile data yet
          </div>
        )}
      </div>
    </div>
  )
}
