import json
import os
from collections import Counter
from datetime import datetime

LOG_FILE = "/home/mutune/honeypot/honeypot.log"

export interface Attack {
  attacker_ip: string
  attacker_port: number
  honeypot_port: number
  service: string
  timestamp: string
  info: {
    ip: string
    timestamp: string
    geolocation: Record<string, unknown>
    asn: string
    isp: string
    country: string
    city: string
    os_hints: string[]
    attack_signature: string
    reverse_dns: string
  }
}

export interface Analytics {
  totalAttacks: number
  uniqueAttackers: number
  services: { name: string; count: number }[]
  countries: { name: string; count: number }[]
  attackTypes: { name: string; count: number }[]
  recentAttacks: Attack[]
  firstAttack: string
  lastAttack: string
}

export async function getAnalytics(): Promise<Analytics> {
  const attacks: Attack[] = []

  if (!os.path.exists(LOG_FILE)) {
    return {
      totalAttacks: 0,
      uniqueAttackers: 0,
      services: [],
      countries: [],
      attackTypes: [],
      recentAttacks: [],
      firstAttack: 'N/A',
      lastAttack: 'N/A',
    }
  }

  const content = await Bun.file(LOG_FILE).text()
  const lines = content.split('\n').filter(line => line.trim().startsWith('{'))

  for (const line of lines) {
    try {
      attacks.push(JSON.parse(line))
    } catch {
      continue
    }
  }

  if (attacks.length === 0) {
    return {
      totalAttacks: 0,
      uniqueAttackers: 0,
      services: [],
      countries: [],
      attackTypes: [],
      recentAttacks: [],
      firstAttack: 'N/A',
      lastAttack: 'N/A',
    }
  }

  const services = Counter(attacks.map(a => a.service))
  const countries = Counter(
    attacks
      .map(a => a.info?.country)
      .filter(c => c && c !== 'Unknown' && c !== 'Localhost')
  )
  const attackTypes = Counter(
    attacks
      .map(a => a.info?.attack_signature?.split(' - ')[0] || 'Unknown')
      .filter(t => t && t !== 'Unknown')
  )

  const timestamps = attacks.map(a => a.timestamp).filter(Boolean)
  const firstAttack = timestamps.length > 0 ? timestamps.sort()[0] : 'N/A'
  const lastAttack = timestamps.length > 0 ? timestamps.sort()[timestamps.length - 1] : 'N/A'

  return {
    totalAttacks: attacks.length,
    uniqueAttackers: new Set(attacks.map(a => a.attacker_ip)).size,
    services: services.map(([name, count]) => ({ name, count })).slice(0, 10),
    countries: countries.map(([name, count]) => ({ name, count })).slice(0, 10),
    attackTypes: attackTypes.map(([name, count]) => ({ name, count })).slice(0, 10),
    recentAttacks: attacks.slice(-20).reverse(),
    firstAttack: firstAttack.slice(0, 19),
    lastAttack: lastAttack.slice(0, 19),
  }
}
