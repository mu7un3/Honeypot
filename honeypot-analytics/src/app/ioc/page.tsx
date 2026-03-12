"use client"

import { useState, useEffect } from "react"
import { Download, FileText, RefreshCw, Shield, AlertTriangle } from "lucide-react"

interface IOC {
  ip: string
  first_seen: string
  last_seen: string
  attack_count: number
  threat_score: number
  severity: string
  country: string
  services_targeted: string[]
}

export default function IOCPage() {
  const [iocs, setIocs] = useState<IOC[]>([])
  const [loading, setLoading] = useState(true)
  const [exporting, setExporting] = useState(false)

  const fetchIOCs = async () => {
    try {
      const res = await fetch("/api/analytics")
      const data = await res.json()
      // Transform recent attacks into IOC format
      const iocList: IOC[] = (data.recentAttacks || []).map((attack: any) => ({
        ip: attack.attacker_ip,
        first_seen: attack.timestamp,
        last_seen: attack.timestamp,
        attack_count: attack.hit_count || 1,
        threat_score: attack.threat_score || 0,
        severity: attack.severity || "INFO",
        country: attack.info?.country || "Unknown",
        services_targeted: [attack.service || "Unknown"],
      }))
      // Deduplicate by IP
      const uniqueIocs = Array.from(
        new Map(iocs.map((ioc) => [ioc.ip, ioc])).values()
      )
      setIocs(uniqueIocs)
    } catch (err) {
      console.error("Failed to fetch IOCs:", err)
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
    fetchIOCs()
  }, [])

  const criticalCount = iocs.filter(i => i.severity === "CRITICAL").length
  const highCount = iocs.filter(i => i.severity === "HIGH").length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">IOC Export</h1>
          <p className="text-zinc-400 text-sm mt-1">Indicators of Compromise for threat intelligence sharing</p>
        </div>
        <button
          onClick={exportIOC}
          disabled={exporting || iocs.length === 0}
          className="flex items-center gap-2 px-4 py-2 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition text-sm font-medium"
        >
          <Download className={`w-4 h-4 ${exporting ? "animate-bounce" : ""}`} />
          Export IOC ({iocs.length})
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <FileText className="w-5 h-5 text-blue-500" />
            <span className="text-zinc-400 text-sm">Total IOCs</span>
          </div>
          <p className="text-3xl font-bold">{iocs.length}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-5 h-5 text-red-600" />
            <span className="text-zinc-400 text-sm">Critical</span>
          </div>
          <p className="text-3xl font-bold">{criticalCount}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle className="w-5 h-5 text-orange-500" />
            <span className="text-zinc-400 text-sm">High</span>
          </div>
          <p className="text-3xl font-bold">{highCount}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Download className="w-5 h-5 text-green-500" />
            <span className="text-zinc-400 text-sm">Ready to Export</span>
          </div>
          <p className="text-3xl font-bold">{iocs.length > 0 ? "Yes" : "No"}</p>
        </div>
      </div>

      {/* IOC List */}
      <div className="bg-zinc-900 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <FileText className="w-5 h-5 text-blue-500" />
            Indicators of Compromise
          </h2>
          <button
            onClick={fetchIOCs}
            className="flex items-center gap-2 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 rounded-lg transition text-xs"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>

        {iocs.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="w-16 h-16 text-zinc-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">No IOCs Available</h3>
            <p className="text-zinc-400 text-sm">Indicators will appear here once attacks are detected.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-zinc-500 border-b border-zinc-700 text-xs">
                  <th className="pb-3 pr-3">IP Address</th>
                  <th className="pb-3 pr-3">Country</th>
                  <th className="pb-3 pr-3">Severity</th>
                  <th className="pb-3 pr-3">Threat Score</th>
                  <th className="pb-3 pr-3">Attacks</th>
                  <th className="pb-3 pr-3">Services</th>
                  <th className="pb-3">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc, i) => (
                  <tr key={i} className="border-b border-zinc-800 hover:bg-zinc-800/60">
                    <td className="py-3 pr-3 font-mono text-xs">{ioc.ip}</td>
                    <td className="py-3 pr-3 text-xs text-zinc-400">{ioc.country}</td>
                    <td className="py-3 pr-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                        ioc.severity === "CRITICAL" ? "bg-red-500/20 text-red-400" :
                        ioc.severity === "HIGH" ? "bg-orange-500/20 text-orange-400" :
                        ioc.severity === "MEDIUM" ? "bg-yellow-500/20 text-yellow-400" :
                        "bg-green-500/20 text-green-400"
                      }`}>
                        {ioc.severity}
                      </span>
                    </td>
                    <td className="py-3 pr-3">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 bg-zinc-700 rounded-full h-2 w-20">
                          <div
                            className={`h-2 rounded-full ${
                              ioc.threat_score >= 8 ? "bg-red-500" :
                              ioc.threat_score >= 6 ? "bg-orange-500" :
                              ioc.threat_score >= 4 ? "bg-yellow-500" : "bg-green-500"
                            }`}
                            style={{ width: `${Math.min(100, (ioc.threat_score / 10) * 100)}%` }}
                          />
                        </div>
                        <span className="text-xs font-mono w-8 text-right">{ioc.threat_score.toFixed(1)}</span>
                      </div>
                    </td>
                    <td className="py-3 pr-3 text-xs">{ioc.attack_count}</td>
                    <td className="py-3 pr-3">
                      <div className="flex flex-wrap gap-1">
                        {ioc.services_targeted.slice(0, 3).map((svc, j) => (
                          <span key={j} className="px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded text-xs">
                            {svc}
                          </span>
                        ))}
                        {ioc.services_targeted.length > 3 && (
                          <span className="text-xs text-zinc-500">+{ioc.services_targeted.length - 3}</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 text-xs font-mono text-zinc-400">{ioc.last_seen?.slice(0, 16)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Export Info */}
      <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-blue-400 mb-2">About IOC Export</h3>
        <p className="text-xs text-zinc-400 leading-relaxed">
          The exported JSON file contains all indicators of compromise detected by the honeypot, including IP addresses,
          threat scores, severity levels, and targeted services. This data can be imported into SIEM systems, firewall
          blocklists, or shared with threat intelligence platforms like AbuseIPDB, MISP, or OpenCTI.
        </p>
      </div>
    </div>
  )
}
