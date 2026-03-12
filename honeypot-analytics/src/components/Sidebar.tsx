"use client"

import { useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  Shield,
  LayoutDashboard,
  Activity,
  Globe,
  Brain,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Server,
  Users,
  AlertTriangle,
} from "lucide-react"

const navItems = [
  { name: "Dashboard", href: "/", icon: LayoutDashboard },
  { name: "Live Feed", href: "/live", icon: Activity },
  { name: "Attack Map", href: "/map", icon: Globe },
  { name: "ML Analysis", href: "/analysis", icon: Brain },
  { name: "IOC Export", href: "/ioc", icon: FileText },
  { name: "Settings", href: "/settings", icon: Settings },
]

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const pathname = usePathname()

  return (
    <aside
      className={`fixed left-0 top-0 h-full bg-zinc-900 border-r border-zinc-800 transition-all duration-300 z-40 ${
        collapsed ? "w-16" : "w-64"
      }`}
    >
      {/* Logo Section */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-zinc-800">
        <div className={`flex items-center gap-3 ${collapsed ? "justify-center w-full" : ""}`}>
          <Shield className="w-8 h-8 text-red-500 flex-shrink-0" />
          {!collapsed && (
            <span className="font-bold text-lg text-white">Honeypot</span>
          )}
        </div>
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="p-1.5 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-white transition hidden md:block"
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <ChevronLeft className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="p-3 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon
          const isActive = pathname === item.href
          return (
            <Link
              key={item.name}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all ${
                isActive
                  ? "bg-red-500/20 text-red-400 border border-red-500/30"
                  : "text-zinc-400 hover:bg-zinc-800 hover:text-white"
              } ${collapsed ? "justify-center" : ""}`}
              title={collapsed ? item.name : undefined}
            >
              <Icon className="w-5 h-5 flex-shrink-0" />
              {!collapsed && <span className="text-sm font-medium">{item.name}</span>}
            </Link>
          )
        })}
      </nav>

      {/* Quick Stats */}
      {!collapsed && (
        <div className="absolute bottom-20 left-0 right-0 p-4">
          <div className="bg-zinc-800/50 rounded-lg p-3 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-zinc-400 flex items-center gap-2">
                <Server className="w-3 h-3" /> Ports Active
              </span>
              <span className="text-white font-mono">50+</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zinc-400 flex items-center gap-2">
                <Users className="w-3 h-3" /> Monitored
              </span>
              <span className="text-green-400 font-mono">24/7</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-zinc-400 flex items-center gap-2">
                <AlertTriangle className="w-3 h-3" /> Threat Level
              </span>
              <span className="text-orange-400 font-mono">ELEVATED</span>
            </div>
          </div>
        </div>
      )}

      {/* Version */}
      <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-zinc-800">
        <div className={`flex items-center gap-2 ${collapsed ? "justify-center" : ""}`}>
          <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
          {!collapsed && (
            <span className="text-xs text-zinc-500">v2.0 · ML-Enhanced</span>
          )}
        </div>
      </div>
    </aside>
  )
}
