import { NextResponse } from "next/server"
import { readFile } from "fs/promises"
import { existsSync } from "fs"
import { join } from "path"

// ── Log file path — env var first, fallback to sibling honeypot dir ───────────
const LOG_FILE =
  process.env.HONEYPOT_LOG_FILE ||
  join(process.cwd(), "..", "honeypot", "honeypot.log")

// ── Types ─────────────────────────────────────────────────────────────────────

interface MLAnalysis {
  attack_type?: { predicted_type?: string; confidence?: number; model?: string }
  anomaly?:     { is_anomaly?: boolean; anomaly_score?: number; interpretation?: string }
  threat?:      { threat_score?: number; severity?: string; recommendations?: string[]; ml_score?: number; rule_score?: number }
  cluster?:     { cluster?: number; profile?: string }
  timestamp?:   string
}

interface Attack {
  attacker_ip:      string
  attacker_port:    number
  honeypot_port:    number
  service:          string
  timestamp:        string
  hit_count?:       number
  payload_decoded?: string
  payload_hex?:     string
  ml_features?:     Record<string, unknown>
  ml_analysis?:     MLAnalysis
  info: {
    ip:                string
    country:           string
    city:              string
    isp?:              string
    asn?:              string
    org?:              string
    attack_signature:  string
    reverse_dns?:      string
    lat?:              number
    lon?:              number
    threat_indicators?: string[]
    whois?:            string
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function countByField(attacks: Attack[], field: string): { name: string; count: number }[] {
  const counts = new Map<string, number>()
  for (const a of attacks) {
    let key = "Unknown"
    if (field === "service") {
      key = a.service
    } else if (field === "country") {
      key = a.info?.country
      if (!key || key === "Unknown" || key === "Localhost") continue
    } else if (field === "attackType") {
      key = a.ml_analysis?.attack_type?.predicted_type
        || a.info?.attack_signature?.split(" — ")[0]
        || "Unknown"
      if (!key || key === "Unknown") continue
    } else if (field === "severity") {
      key = a.ml_analysis?.threat?.severity || "Unknown"
      if (key === "Unknown") continue
    } else if (field === "profile") {
      key = a.ml_analysis?.cluster?.profile || "Unknown"
      if (key === "Unknown") continue
    }
    counts.set(key, (counts.get(key) || 0) + 1)
  }
  return Array.from(counts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)
}

function buildTimeline(attacks: Attack[]): { time: string; count: number }[] {
  const buckets = new Map<string, number>()
  const cutoff  = Date.now() - 24 * 60 * 60 * 1000
  for (const a of attacks) {
    const ts = new Date(a.timestamp).getTime()
    if (isNaN(ts) || ts < cutoff) continue
    const bucket = new Date(Math.floor(ts / (10 * 60 * 1000)) * (10 * 60 * 1000))
      .toISOString().slice(0, 16)
    buckets.set(bucket, (buckets.get(bucket) || 0) + 1)
  }
  return Array.from(buckets.entries())
    .map(([time, count]) => ({ time, count }))
    .sort((a, b) => a.time.localeCompare(b.time))
}

function avgThreatScore(attacks: Attack[]): number {
  const scores = attacks
    .map(a => a.ml_analysis?.threat?.threat_score)
    .filter((s): s is number => typeof s === "number")
  if (!scores.length) return 0
  return Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10
}

// ── GET /api/analytics ────────────────────────────────────────────────────────

export async function GET() {
  const empty = {
    totalAttacks: 0, uniqueAttackers: 0, blockedIPs: 0,
    avgThreatScore: 0, criticalCount: 0, anomalyCount: 0,
    services: [], countries: [], attackTypes: [], severities: [],
    attackerProfiles: [], recentAttacks: [], attackLocations: [],
    timeline: [], firstAttack: "N/A", lastAttack: "N/A",
  }

  try {
    if (!existsSync(LOG_FILE)) return NextResponse.json(empty)

    const content  = await readFile(LOG_FILE, "utf-8")
    const attacks: Attack[] = []
    for (const line of content.split("\n")) {
      const t = line.trim()
      if (!t.startsWith("{")) continue
      try { attacks.push(JSON.parse(t)) } catch { continue }
    }
    if (attacks.length === 0) return NextResponse.json(empty)

    const timestamps = attacks.map(a => a.timestamp).filter(Boolean).sort()

    // Count blocked IPs from file if present
    const blockedFile = LOG_FILE.replace("honeypot.log", "blocked_ips.txt")
    const blockedCount = existsSync(blockedFile)
      ? (await readFile(blockedFile, "utf-8")).split("\n").filter(Boolean).length
      : 0

    const criticalCount = attacks.filter(a => a.ml_analysis?.threat?.severity === "CRITICAL").length
    const anomalyCount  = attacks.filter(a => a.ml_analysis?.anomaly?.is_anomaly === true).length

    return NextResponse.json({
      totalAttacks:     attacks.length,
      uniqueAttackers:  new Set(attacks.map(a => a.attacker_ip)).size,
      blockedIPs:       blockedCount,
      avgThreatScore:   avgThreatScore(attacks),
      criticalCount,
      anomalyCount,
      services:         countByField(attacks, "service"),
      countries:        countByField(attacks, "country"),
      attackTypes:      countByField(attacks, "attackType"),
      severities:       countByField(attacks, "severity"),
      attackerProfiles: countByField(attacks, "profile"),
      timeline:         buildTimeline(attacks),
      recentAttacks: attacks.slice(-50).reverse().map(a => ({
        attacker_ip:     a.attacker_ip,
        attacker_port:   a.attacker_port,
        honeypot_port:   a.honeypot_port,
        service:         a.service,
        timestamp:       a.timestamp,
        hit_count:       a.hit_count || 1,
        payload_decoded: a.payload_decoded || "",
        threat_score:    a.ml_analysis?.threat?.threat_score   ?? null,
        severity:        a.ml_analysis?.threat?.severity        ?? null,
        attack_type:     a.ml_analysis?.attack_type?.predicted_type ?? null,
        is_anomaly:      a.ml_analysis?.anomaly?.is_anomaly      ?? false,
        profile:         a.ml_analysis?.cluster?.profile         ?? null,
        indicators:      a.info?.threat_indicators               ?? [],
        info: {
          country:          a.info?.country           || "Unknown",
          city:             a.info?.city              || "Unknown",
          isp:              a.info?.isp               || "Unknown",
          asn:              a.info?.asn               || "Unknown",
          attack_signature: a.info?.attack_signature  || "",
          reverse_dns:      a.info?.reverse_dns        || "",
          lat:              a.info?.lat ?? 0,
          lon:              a.info?.lon ?? 0,
        },
      })),
      attackLocations: attacks
        .filter(a => a.info?.lat && a.info?.lon && a.info.lat !== 0 && a.info.lon !== 0)
        .slice(-100)
        .map(a => ({
          ip:           a.attacker_ip,
          lat:          a.info.lat!,
          lon:          a.info.lon!,
          country:      a.info.country || "Unknown",
          city:         a.info.city    || "Unknown",
          service:      a.service,
          timestamp:    a.timestamp,
          threat_score: a.ml_analysis?.threat?.threat_score ?? 0,
          severity:     a.ml_analysis?.threat?.severity     ?? "INFO",
        })),
      firstAttack: timestamps[0]?.slice(0, 19)                      ?? "N/A",
      lastAttack:  timestamps[timestamps.length - 1]?.slice(0, 19)  ?? "N/A",
    })
  } catch (error) {
    console.error("Analytics error:", error)
    return NextResponse.json({ error: "Failed to load analytics" }, { status: 500 })
  }
}

// ── POST /api/analytics → IOC export download ─────────────────────────────────

export async function POST() {
  const iocFile = LOG_FILE.replace("honeypot.log", "ioc_export.json")
  try {
    if (!existsSync(iocFile)) return NextResponse.json({ iocs: [] })
    const data = await readFile(iocFile, "utf-8")
    return new Response(data, {
      headers: {
        "Content-Type":        "application/json",
        "Content-Disposition": `attachment; filename="ioc_export_${new Date().toISOString().slice(0, 10)}.json"`,
      },
    })
  } catch {
    return NextResponse.json({ error: "Failed to read IOC file" }, { status: 500 })
  }
}
