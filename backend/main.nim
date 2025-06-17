import os
import utils/env # Import env utils first
loadEnvFile()     # Load .env file immediately

import jester
import db/db
import times, strutils, json, random, options
import nimcrypto/random as cryptoRandom # For cryptographically secure random bytes

# Import route modules
import routes/login
import routes/register
import routes/dashboard
import routes/mfa
import routes/email_verification_routes
import utils/ddos_protector # Import DDoS Protector

# --- Helper Procedures ---

proc generateSecureRandomToken(length: int = 32): string =
  # Generate cryptographically secure random bytes and hex encode them
  var bytes: seq[byte]
  if length > 0:
    bytes = newSeq[byte](length)
    # Ensure randomBytes is called correctly for a seq.
    # Nim's randomBytes typically takes an openArray. Casting or using addr.
    if bytes.len > 0: # Check sequence is not empty before accessing addr bytes[0]
      cryptoRandom.randomBytes(bytes[0].addr, length)
  else:
    return "" # Or raise error for invalid length
  
  result = ""
  for b in bytes:
    result.add b.toHex(2).toLowerAscii()

proc getClientIp(request: Request): string =
  # Order of preference: X-Forwarded-For (if multiple, take first), X-Real-IP, remoteAddress
  var ip = request.headers.getOrDefault("X-Forwarded-For", "")
  if ip.len > 0:
    let parts = ip.split(',')
    if parts.len > 0:
      let firstIp = parts[0].strip()
      if firstIp.len > 0: return firstIp
  
  ip = request.headers.getOrDefault("X-Real-IP", "")
  if ip.len > 0:
    return ip
  
  return request.remoteAddress

# --- Jester Routes ---

routes:
  before hook(request):
    let clientIp = getClientIp(request)
    if clientIp.len == 0:
      echo "[ERROR] Could not determine client IP."
      resp Http500, "Internal Server Error: Cannot identify client."
      finish()

    # Check if IP is currently banned (from DB)
    let blockedStatusOption = await getBlockedStatus(clientIp)
    if blockedStatusOption.isSome:
      let blockedUntil = blockedStatusOption.get
      if blockedUntil > now():
        echo "[WARN] Blocked IP attempted access: ", clientIp, " - Blocked until: ", $blockedUntil
        resp Http403, "Access denied. Your IP is currently blocked."
        finish()

    # Check for rate limiting (in-memory check, then potential ban via DB)
    if await isRateLimited(clientIp):
      echo "[WARN] Rate limit exceeded by IP (hook): ", clientIp
      resp Http429, "Too many requests. Your IP has been temporarily blocked."
      finish()

  get "/csrf-token":
    let sessionTokenCookie = request.cookies.getOrDefault("session", "")
    var userSession: Session
    var isExistingSession = false

    if sessionTokenCookie.len > 0:
      ensureDbConnection()
      userSession = dbGetSessionByToken(sessionTokenCookie)
      if userSession.id != 0:
        isExistingSession = true

    let newCsrfToken = generateSecureRandomToken()

    if isExistingSession:
      if dbUpdateSessionCsrfToken(userSession.sessionToken, newCsrfToken):
        echo "[CSRF] Updated CSRF token in session for user ID: ", userSession.userId
        resp Http200, newCsrfToken
      else:
        echo "[CSRF ERROR] Failed to update CSRF token in session database for user ID: ", userSession.userId
        resp Http500, "Error generating CSRF token (session update failed)."
    else:
      var cookie = newCookie("csrf_token_value", newCsrfToken, expires = now() + 30.minutes)
      cookie.path = "/"
      # cookie.secure = true # Enable for HTTPS if your service is HTTPS-only
      cookie.sameSite = SameSite.Strict
      setCookie(cookie)
      echo "[CSRF] Issued CSRF token via double submit cookie method."
      resp Http200, newCsrfToken

  get "/captcha":
    let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    var text = ""
    randomize()
    for i in 0..<6:
      text.add chars[rand(chars.len - 1)]
    
    let svg = """<svg width="160" height="60" xmlns="http://www.w3.org/2000/svg">
  <rect width="160" height="60" fill="#f8f9fa" stroke="#dee2e6"/>
  <text x="80" y="35" font-family="monospace" font-size="24" text-anchor="middle" fill="#495057">""" & text & """</text>
  <line x1="10" y1="15" x2="150" y2="45" stroke="#adb5bd" stroke-width="1"/>
  <line x1="30" y1="50" x2="130" y2="10" stroke="#adb5bd" stroke-width="1"/>
  <line x1="20" y1="10" x2="140" y2="30" stroke="#adb5bd" stroke-width="1"/>
</svg>"""
    resp Http200, svg, "image/svg+xml"

# --- Main Execution ---

when isMainModule:
  echo "[MAIN] Starting application..."
  loadEnvFile() # Load .env first
  echo "[DEBUG] Environment loaded"
  
  let dbUrl = getEnv("DB_URL")
  echo "[DEBUG] DB_URL: ", if dbUrl.len > 0: "SET (length=" & $dbUrl.len & ")" else: "NOT SET"
  # echo "[DEBUG] Full DB_URL: ", dbUrl # Potentially sensitive, comment out for prod logs

  let portEnv = getEnv("PORT", "5000")
  var portNum = 5000
  try:
    portNum = parseInt(portEnv)
  except ValueError:
    echo "[WARN] Invalid PORT value '", portEnv, "', defaulting to 5000."
  
  echo "[INFO] Starting server on port ", portNum
  
  # Initialize database connection
  echo "[MAIN] Calling connectDb()..."
  try:
    connectDb()
    echo "[MAIN] Database connection completed"
  except Exception as e:
    echo "[MAIN ERROR] Database connection failed: ", e.msg
    quit(1)

  # Initialize DDoS Protector
  initDdosProtector()

  # Start Jester server
  echo "[MAIN] Starting Jester server..."
  runForever()
