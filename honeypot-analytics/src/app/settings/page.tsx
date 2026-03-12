"use client"

import { useState } from "react"
import { Settings, Save, Mail, Database, Shield, AlertTriangle } from "lucide-react"

export default function SettingsPage() {
  const [saved, setSaved] = useState(false)
  const [formData, setFormData] = useState({
    smtpServer: "smtp.gmail.com",
    smtpPort: "587",
    senderEmail: "",
    senderPassword: "",
    recipientEmail: "",
    emailThrottle: "300",
    emailMaxPerHour: "20",
    abuseipdbKey: "",
    maxHandlerThreads: "50",
  })

  const handleSave = () => {
    // In production, this would save to .env file via API
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData({ ...formData, [e.target.name]: e.target.value })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">System Settings</h1>
          <p className="text-zinc-400 text-sm mt-1">Configure honeypot behavior and alerting</p>
        </div>
        <button
          onClick={handleSave}
          className="flex items-center gap-2 px-4 py-2 bg-green-500 hover:bg-green-600 rounded-lg transition text-sm font-medium"
        >
          <Save className="w-4 h-4" />
          {saved ? "Saved!" : "Save Changes"}
        </button>
      </div>

      {/* Configuration Info */}
      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="text-sm font-semibold text-yellow-400 mb-1">Configuration File</h3>
            <p className="text-xs text-zinc-400">
              Settings are stored in <code className="bg-zinc-800 px-1.5 py-0.5 rounded">honeypot/.env</code>. 
              After saving, restart the honeypot service for changes to take effect.
            </p>
          </div>
        </div>
      </div>

      {/* Email Settings */}
      <div className="bg-zinc-900 rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Mail className="w-5 h-5 text-blue-500" />
          Email Alert Configuration
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">SMTP Server</label>
            <input
              type="text"
              name="smtpServer"
              value={formData.smtpServer}
              onChange={handleChange}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="smtp.gmail.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">SMTP Port</label>
            <input
              type="text"
              name="smtpPort"
              value={formData.smtpPort}
              onChange={handleChange}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="587"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">Sender Email</label>
            <input
              type="email"
              name="senderEmail"
              value={formData.senderEmail}
              onChange={handleChange}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="your_email@gmail.com"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">App Password</label>
            <input
              type="password"
              name="senderPassword"
              value={formData.senderPassword}
              onChange={handleChange}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="xxxx-xxxx-xxxx-xxxx"
            />
          </div>
          <div className="md:col-span-2">
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">Recipient Email</label>
            <input
              type="email"
              name="recipientEmail"
              value={formData.recipientEmail}
              onChange={handleChange}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="alerts@yourcompany.com"
            />
          </div>
        </div>
      </div>

      {/* Alert Throttling */}
      <div className="bg-zinc-900 rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5 text-green-500" />
          Alert Throttling
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">
              Email Throttle (seconds)
            </label>
            <input
              type="number"
              name="emailThrottle"
              value={formData.emailThrottle}
              onChange={handleChange}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
            />
            <p className="text-xs text-zinc-500 mt-1">Minimum seconds between emails to same IP</p>
          </div>
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">
              Max Emails Per Hour
            </label>
            <input
              type="number"
              name="emailMaxPerHour"
              value={formData.emailMaxPerHour}
              onChange={handleChange}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
            />
            <p className="text-xs text-zinc-500 mt-1">Global email rate limit</p>
          </div>
        </div>
      </div>

      {/* Integration Settings */}
      <div className="bg-zinc-900 rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Database className="w-5 h-5 text-purple-500" />
          External Integrations
        </h2>
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">
              AbuseIPDB API Key
            </label>
            <input
              type="password"
              name="abuseipdbKey"
              value={formData.abuseipdbKey}
              onChange={handleChange}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
              placeholder="Enter your AbuseIPDB API key"
            />
            <p className="text-xs text-zinc-500 mt-1">
              Auto-report malicious IPs to AbuseIPDB (Tier 2 responses)
            </p>
          </div>
        </div>
      </div>

      {/* System Settings */}
      <div className="bg-zinc-900 rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Settings className="w-5 h-5 text-zinc-400" />
          System Configuration
        </h2>
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1.5">
              Max Handler Threads
            </label>
            <input
              type="number"
              name="maxHandlerThreads"
              value={formData.maxHandlerThreads}
              onChange={handleChange}
              className="w-full bg-zinc-800 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
            />
            <p className="text-xs text-zinc-500 mt-1">
              Maximum concurrent connection handlers (default: 50)
            </p>
          </div>
        </div>
      </div>

      {/* Quick Links */}
      <div className="bg-zinc-900 rounded-xl p-6">
        <h2 className="text-lg font-semibold mb-4">Quick Links</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <a
            href="https://support.google.com/accounts/answer/185833"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 p-3 bg-zinc-800 hover:bg-zinc-700 rounded-lg transition text-sm"
          >
            <Mail className="w-4 h-4 text-blue-500" />
            <span>Get Gmail App Password</span>
          </a>
          <a
            href="https://www.abuseipdb.com/api"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 p-3 bg-zinc-800 hover:bg-zinc-700 rounded-lg transition text-sm"
          >
            <Database className="w-4 h-4 text-purple-500" />
            <span>Get AbuseIPDB API Key</span>
          </a>
        </div>
      </div>
    </div>
  )
}
