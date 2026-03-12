"use client"

import { useState, useEffect } from "react"
import {
  Shield,
  Bell,
  Search,
  Wifi,
  WifiOff,
  Server,
  Clock,
  X,
} from "lucide-react"

interface HeaderProps {
  title?: string
}

export default function Header({ title = "Dashboard" }: HeaderProps) {
  const [isOnline, setIsOnline] = useState(true)
  const [lastSync, setLastSync] = useState<Date>(new Date())
  const [showNotifications, setShowNotifications] = useState(false)
  const [notifications, setNotifications] = useState<Array<{
    id: number
    type: "critical" | "warning" | "info"
    message: string
    time: string
  }>>([])

  // Check honeypot connection status
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const res = await fetch("/api/analytics")
        if (res.ok) {
          setIsOnline(true)
          setLastSync(new Date())
        } else {
          setIsOnline(false)
        }
      } catch {
        setIsOnline(false)
      }
    }

    checkStatus()
    const interval = setInterval(checkStatus, 10000)
    return () => clearInterval(interval)
  }, [])

  // Simulate notifications (in production, fetch from API)
  useEffect(() => {
    // Check for new attacks periodically
    const checkNotifications = async () => {
      try {
        const res = await fetch("/api/analytics")
        const data = await res.json()
        if (data.totalAttacks > 0) {
          const newNotifications: typeof notifications = []
          
          if (data.criticalCount > 0) {
            newNotifications.push({
              id: Date.now(),
              type: "critical",
              message: `${data.criticalCount} critical attack(s) detected`,
              time: new Date().toLocaleTimeString(),
            })
          }
          
          if (data.anomalyCount > 0) {
            newNotifications.push({
              id: Date.now() + 1,
              type: "warning",
              message: `${data.anomalyCount} anomaly/anomalies detected`,
              time: new Date().toLocaleTimeString(),
            })
          }

          if (newNotifications.length > 0) {
            setNotifications(prev => [...newNotifications, ...prev].slice(0, 10))
          }
        }
      } catch {
        // Ignore errors
      }
    }

    checkNotifications()
    const interval = setInterval(checkNotifications, 30000)
    return () => clearInterval(interval)
  }, [])

  const unreadCount = notifications.length

  return (
    <header className="h-16 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between px-6 sticky top-0 z-30">
      {/* Left: Page Title */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-red-500" />
          <div>
            <h1 className="text-lg font-bold text-white">Honeypot Analytics</h1>
            <p className="text-xs text-zinc-500">{title}</p>
          </div>
        </div>
      </div>

      {/* Center: Search (optional) */}
      <div className="hidden md:flex items-center gap-2 bg-zinc-800 rounded-lg px-3 py-2 w-64">
        <Search className="w-4 h-4 text-zinc-500" />
        <input
          type="text"
          placeholder="Search attacks, IPs..."
          className="bg-transparent text-sm text-white placeholder-zinc-500 outline-none w-full"
        />
      </div>

      {/* Right: Status & Actions */}
      <div className="flex items-center gap-4">
        {/* Connection Status */}
        <div className="flex items-center gap-2 px-3 py-1.5 bg-zinc-800 rounded-lg">
          {isOnline ? (
            <>
              <Wifi className="w-4 h-4 text-green-500" />
              <span className="text-sm text-green-400 font-medium">Online</span>
            </>
          ) : (
            <>
              <WifiOff className="w-4 h-4 text-red-500" />
              <span className="text-sm text-red-400 font-medium">Offline</span>
            </>
          )}
          <span className="text-xs text-zinc-500 ml-2 hidden lg:inline">
            {lastSync.toLocaleTimeString()}
          </span>
        </div>

        {/* Server Status */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 bg-zinc-800 rounded-lg">
          <Server className="w-4 h-4 text-blue-500" />
          <span className="text-sm text-zinc-300">50+ Ports</span>
        </div>

        {/* Notifications */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-lg hover:bg-zinc-800 transition"
          >
            <Bell className="w-5 h-5 text-zinc-400" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center font-bold">
                {unreadCount}
              </span>
            )}
          </button>

          {/* Notifications Dropdown */}
          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-zinc-900 border border-zinc-800 rounded-xl shadow-xl overflow-hidden z-50">
              <div className="p-4 border-b border-zinc-800 flex items-center justify-between">
                <h3 className="font-semibold text-white">Notifications</h3>
                <button
                  onClick={() => setNotifications([])}
                  className="text-xs text-zinc-500 hover:text-white"
                >
                  Clear all
                </button>
              </div>
              <div className="max-h-64 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="p-8 text-center text-zinc-500 text-sm">
                    No new notifications
                  </div>
                ) : (
                  notifications.map((notif) => (
                    <div
                      key={notif.id}
                      className="p-4 border-b border-zinc-800 hover:bg-zinc-800/50 transition"
                    >
                      <div className="flex items-start gap-3">
                        <div
                          className={`w-2 h-2 rounded-full mt-1.5 ${
                            notif.type === "critical"
                              ? "bg-red-500"
                              : notif.type === "warning"
                              ? "bg-orange-500"
                              : "bg-blue-500"
                          }`}
                        />
                        <div className="flex-1">
                          <p className="text-sm text-white">{notif.message}</p>
                          <p className="text-xs text-zinc-500 mt-1">{notif.time}</p>
                        </div>
                        <button
                          onClick={() =>
                            setNotifications(prev => prev.filter(n => n.id !== notif.id))
                          }
                          className="text-zinc-500 hover:text-white"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Clock */}
        <div className="hidden xl:flex items-center gap-2 text-zinc-400">
          <Clock className="w-4 h-4" />
          <span className="text-sm font-mono">{new Date().toLocaleTimeString()}</span>
        </div>
      </div>
    </header>
  )
}
