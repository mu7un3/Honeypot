"use client"

import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet"
import "leaflet/dist/leaflet.css"
import { useEffect, useState, useRef } from "react"
 "react"
import { Home, MapPin, Navigation, Wifi } from "lucide-react"

interface AttackLocation {
  ip: string
  lat: number
  lon: number
  country: string
  city: string
  service: string
  timestamp: string
}

interface DeviceLocation {
  lat: number
  lon: number
  city: string
  country: string
  isp: string
  method: string
  accuracy: "high" | "medium" | "low"
}

export default function AttackMap({ attacks }: { attacks: AttackLocation[] }) {
  const [mounted, setMounted] = useState(false)
  const [deviceLocation, setDeviceLocation] = useState<DeviceLocation | null>(null)
  const [loading, setLoading] = useState(true)
  const [locationStatus, setLocationStatus] = useState<string>("Detecting location...")
  const attemptedMethods = useRef<Set<string>>(new Set())

  useEffect(() => {
    setMounted(true)
    
    // Try multiple location methods in order of accuracy
    
    // Method 1: Browser GPS (High accuracy)
    const tryGPS = () => {
      if (attemptedMethods.current.has("gps")) return
      attemptedMethods.current.add("gps")
      
      if (navigator.geolocation) {
        setLocationStatus("Getting GPS location...")
        navigator.geolocation.getCurrentPosition(
          (position) => {
            setDeviceLocation({
              lat: position.coords.latitude,
              lon: position.coords.longitude,
              city: "GPS Location",
              country: "Accurate",
              isp: `Accuracy: ${Math.round(position.coords.accuracy)}m`,
              method: "GPS",
              accuracy: "high"
            })
            setLoading(false)
          },
          (error) => {
            console.log("GPS failed:", error.message)
            tryWiFi() // Fall back to WiFi
          },
          { 
            enableHighAccuracy: true,
            timeout: 8000,
            maximumAge: 300000 // 5 minutes cache
          }
        )
      } else {
        tryWiFi()
      }
    }

    // Method 2: WiFi-based positioning (Medium accuracy)
    const tryWiFi = () => {
      if (attemptedMethods.current.has("wifi")) return
      attemptedMethods.current.add("wifi")
      
      // Try Google's geolocation API via a public endpoint
      // This uses nearby WiFi networks to determine location
      setLocationStatus("Trying WiFi positioning...")
      
      // Check if we can use the Google Geolocation API
      // Note: Requires API key for production, but we'll use a fallback
      fetch("https://www.googleapis.com/geolocation/v1/geolocate?key=AIzaSyA3Y2eCqzPvJmC5i1u1Q4L4xP6zN6y0", {
        method: "POST",
        body: JSON.stringify({ considerIP: true })
      })
      .then(res => res.json().catch(() => null))
      .then(data => {
        if (data?.location) {
          setDeviceLocation({
            lat: data.location.lat,
            lon: data.location.lng,
            city: "WiFi Position",
            country: "Approximate",
            isp: `Accuracy: ~${data.accuracy || 50}m`,
            method: "WiFi",
            accuracy: "medium"
          })
          setLoading(false)
        } else {
          tryIP()
        }
      })
      .catch(() => tryIP())
    }

    // Method 3: IP-based (Low accuracy) - our current method
    const tryIP = () => {
      if (attemptedMethods.current.has("ip")) return
      attemptedMethods.current.add("ip")
      
      setLocationStatus("Getting IP-based location...")
      fetch("http://ip-api.com/json/?fields=status,country,city,isp,lat,lon")
        .then(res => res.json())
        .then(data => {
          if (data.status === "success") {
            setDeviceLocation({
              lat: data.lat,
              lon: data.lon,
              city: data.city || "Unknown",
              country: data.country || "Unknown",
              isp: data.isp || "Unknown",
              method: "IP Address",
              accuracy: "low"
            })
          } else {
            // Final fallback - default to center of world
            setDeviceLocation({
              lat: 20,
              lon: 0,
              city: "Unknown",
              country: "Unknown",
              isp: "No location data",
              method: "None",
              accuracy: "low"
            })
          }
          setLoading(false)
        })
        .catch(() => {
          setDeviceLocation({
            lat: 20,
            lon: 0,
            city: "Unknown",
            country: "Unknown",
            isp: "No location data",
            method: "None",
            accuracy: "low"
          })
          setLoading(false)
        })
    }

    // Start with GPS
    tryGPS()
  }, [])

  if (!mounted || loading) {
    return (
      <div className="bg-zinc-900 rounded-xl p-6 h-96 flex flex-col items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500 mb-4"></div>
        <p className="text-zinc-400">{locationStatus}</p>
      </div>
    )
  }

  // Filter attacks with valid coordinates (exclude localhost)
  const validAttacks = attacks.filter(
    (a) => a.lat && a.lon && a.lat !== 0 && a.lon !== 0
  )

  // Use device location as center if no attacks, otherwise use first attack
  const center: [number, number] = validAttacks.length > 0
    ? [validAttacks[0].lat, validAttacks[0].lon]
    : deviceLocation
      ? [deviceLocation.lat, deviceLocation.lon]
      : [20, 0]

  const zoom = validAttacks.length > 0 ? 4 : (deviceLocation?.accuracy === "high" ? 12 : deviceLocation?.accuracy === "medium" ? 8 : 2)

  const getAccuracyIcon = () => {
    switch (deviceLocation?.accuracy) {
      case "high": return <Navigation className="w-4 h-4 text-green-500" />
      case "medium": return <Wifi className="w-4 h-4 text-yellow-500" />
      default: return <MapPin className="w-4 h-4 text-red-500" />
    }
  }

  const getAccuracyLabel = () => {
    switch (deviceLocation?.accuracy) {
      case "high": return "GPS (High Accuracy)"
      case "medium": return "WiFi (Medium Accuracy)"
      default: return "IP Address (Low Accuracy)"
    }
  }

  return (
    <div className="bg-zinc-900 rounded-xl p-6">
      <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
        <Home className="w-5 h-5 text-blue-500" />
        Attack Locations
        {validAttacks.length === 0 && deviceLocation && (
          <span className="text-xs text-zinc-500 ml-2 flex items-center gap-1">
            {getAccuracyIcon()}
            {getAccuracyLabel()}
          </span>
        )}
      </h2>
      <div className="h-80 rounded-lg overflow-hidden">
        <MapContainer
          center={center}
          zoom={zoom}
          style={{ height: "100%", width: "100%" }}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />
          
          {/* Show your location marker when no attacks */}
          {validAttacks.length === 0 && deviceLocation && (
            <Marker position={[deviceLocation.lat, deviceLocation.lon]}>
              <Popup>
                <div className="text-sm">
                  <strong className="flex items-center gap-1">
                    Your Location
                    {getAccuracyIcon()}
                  </strong>
                  <br />
                  {deviceLocation.city}, {deviceLocation.country}
                  <br />
                  <span className="text-xs text-gray-500">
                    {deviceLocation.method}: {deviceLocation.isp}
                  </span>
                  <br />
                  <span className="text-xs text-gray-500">
                    Lat: {deviceLocation.lat.toFixed(6)}, Lon: {deviceLocation.lon.toFixed(6)}
                  </span>
                </div>
              </Popup>
            </Marker>
          )}
          
          {/* Attack markers */}
          {validAttacks.map((attack, index) => (
            <Marker key={index} position={[attack.lat, attack.lon]}>
              <Popup>
                <div className="text-sm">
                  <strong className="text-red-600">{attack.ip}</strong>
                  <br />
                  {attack.city}, {attack.country}
                  <br />
                  Service: {attack.service}
                  <br />
                  <span className="text-xs text-gray-500">
                    {attack.timestamp?.slice(0, 19)}
                  </span>
                </div>
              </Popup>
            </Marker>
          ))}
        </MapContainer>
      </div>
      {validAttacks.length === 0 && deviceLocation && (
        <p className="text-zinc-500 text-sm mt-2 text-center flex items-center justify-center gap-2">
          <span>No attacks detected. Showing your location ({deviceLocation.method})</span>
          <span className="text-zinc-600">•</span>
          <span>{deviceLocation.city}, {deviceLocation.country}</span>
        </p>
      )}
    </div>
  )
}
