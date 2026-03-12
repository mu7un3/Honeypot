"use client"

import { useState, useEffect } from "react"
import dynamic from "next/dynamic"
import { Globe, RefreshCw, Shield } from "lucide-react"

const AttackMap = dynamic(() => import("@/components/AttackMap"), { ssr: false })

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

export default function MapPage() {
  const [attacks, setAttacks] = useState<AttackLocation[]>([])
  const [loading, setLoading] = useState(true)
  const [autoRefresh, setAutoRefresh] = useState(true)

  const fetchAttacks = async () => {
    try {
      const res = await fetch("/api/analytics")
      const data = await res.json()
      setAttacks(data.attackLocations || [])
    } catch (err) {
      console.error("Failed to fetch attacks:", err)
    }
    setLoading(false)
  }

  useEffect(() => {
    fetchAttacks()
    if (!autoRefresh) return
    const interval = setInterval(fetchAttacks, 5000)
    return () => clearInterval(interval)
  }, [autoRefresh])

  const uniqueCountries = new Set(attacks.map(a => a.country))
  const criticalAttacks = attacks.filter(a => a.severity === "CRITICAL")

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">World Attack Map</h1>
          <p className="text-zinc-400 text-sm mt-1">Geographic distribution of intrusion attempts</p>
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
            <Globe className="w-5 h-5 text-blue-500" />
            <span className="text-zinc-400 text-sm">Total Attacks</span>
          </div>
          <p className="text-3xl font-bold">{attacks.length}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-5 h-5 text-green-500" />
            <span className="text-zinc-400 text-sm">Countries</span>
          </div>
          <p className="text-3xl font-bold">{uniqueCountries.size}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Shield className="w-5 h-5 text-red-600" />
            <span className="text-zinc-400 text-sm">Critical</span>
          </div>
          <p className="text-3xl font-bold">{criticalAttacks.length}</p>
        </div>
        <div className="bg-zinc-900 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-2">
            <Globe className="w-5 h-5 text-orange-500" />
            <span className="text-zinc-400 text-sm">Top Source</span>
          </div>
          <p className="text-lg font-bold truncate">
            {attacks.length > 0 ? 
              Object.entries(attacks.reduce((acc, a) => {
                acc[a.country] = (acc[a.country] || 0) + 1
                return acc
              }, {} as Record<string, number>))
              .sort((a, b) => b[1] - a[1])[0]?.[0] || "N/A" 
              : "N/A"}
          </p>
        </div>
      </div>

      {/* Map */}
      <div className="bg-zinc-900 rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Globe className="w-5 h-5 text-blue-500" />
          Attack Locations
          <span className="ml-auto text-xs text-zinc-500">{attacks.length} geolocated events</span>
        </h2>
        
        {attacks.length === 0 ? (
          <div className="text-center py-12">
            <Globe className="w-16 h-16 text-zinc-600 mx-auto mb-4" />
            <h3 className="text-lg font-semibold text-white mb-2">No Geolocated Attacks</h3>
            <p className="text-zinc-400 text-sm">Attack locations will appear here once detected.</p>
          </div>
        ) : (
          <AttackMap attacks={attacks} />
        )}
      </div>

      {/* Country List */}
      {attacks.length > 0 && (
        <div className="bg-zinc-900 rounded-xl p-6">
          <h2 className="text-lg font-semibold mb-4">Attacks by Country</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {Object.entries(
              attacks.reduce((acc, a) => {
                acc[a.country] = (acc[a.country] || 0) + 1
                return acc
              }, {} as Record<string, number>)
            )
              .sort((a, b) => b[1] - a[1])
              .map(([country, count]) => (
                <div key={country} className="bg-zinc-800 rounded-lg p-3 text-center">
                  <p className="text-xs text-zinc-400 mb-1">{country}</p>
                  <p className="text-xl font-bold text-white">{count}</p>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  )
}
