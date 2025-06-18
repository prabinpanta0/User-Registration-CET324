import os
import utils/env # Import env utils first
loadEnvFile()     # Load .env file immediately

import jester
import db/db
import db/models
import crypto/password
import crypto/aes
import utils/rate_limit
import utils/audit_log
import utils/totp_utils
import times, strutils, json, random, options
import nimcrypto/sysrand as cryptoRandom # For cryptographically secure random bytes

# Import route modules
# import routes/login  # Temporarily commented out due to multiple routes blocks conflict
# import routes/register  # Temporarily commented out due to route conflicts
# import routes/dashboard  # Temporarily commented out due to route conflicts
# import routes/mfa  # Temporarily commented out due to route conflicts  
# import routes/email_verification_routes  # Temporarily commented out due to route conflicts
# import utils/ddos_protector # Import DDoS Protector - Temporarily commented out due to missing collections/ringbuffers

# --- Helper Procedures ---

proc generateSecureRandomToken(length: int = 32): string =
  # Generate cryptographically secure random bytes and hex encode them
  var bytes: seq[byte]
  if length > 0:
    bytes = newSeq[byte](length)
    # Ensure randomBytes is called correctly for a seq.
    # Nim's randomBytes typically takes an openArray. Casting or using addr.
    if bytes.len > 0: # Check sequence is not empty before accessing addr bytes[0]
      discard cryptoRandom.randomBytes(bytes[0].addr, length)
  else:
    return "" # Or raise error for invalid length
  
  result = ""
  for b in bytes:
    result.add b.toHex(2).toLowerAscii()

proc getClientIp(request: Request): string =
  # Order of preference: X-Forwarded-For (if multiple, take first), X-Real-IP, remoteAddress
  var ip = ""
  if request.headers.hasKey("X-Forwarded-For"):
    ip = request.headers["X-Forwarded-For"]
  if ip.len > 0:
    let parts = ip.split(',')
    if parts.len > 0:
      let firstIp = parts[0].strip()
      if firstIp.len > 0: return firstIp
  
  if request.headers.hasKey("X-Real-IP"):
    ip = request.headers["X-Real-IP"]
  else:
    ip = ""
  if ip.len > 0:
    return ip
  
  return "127.0.0.1" # Default fallback IP

# --- Helper Functions ---

# Include captcha verification function
proc verifyCaptcha(ip, captcha: string): bool =
  result = true

# Include validation functions
proc validPassword(password: string): bool =
  result = password.len >= 10

proc validUsername(username: string): bool =
  result = username.len in 3..20

proc validEmail(email: string): bool =
  result = email.contains("@") and email.contains(".") and email.len > 5

# Session management functions
proc createSession(userId: int, temporary: bool = false): string =
  # Generate a random session token
  randomize()
  var token = ""
  for i in 0..<32:
    token.add char(rand(255))

  # Convert to hex string for safe storage
  result = ""
  for c in token:
    result.add c.int.toHex(2).toLowerAscii()

  # Set expiration time
  let expiresAt = if temporary:
    # 10 minutes for MFA verification
    $((epochTime().int64 + 600))
  else:
    # 7 days for regular session
    $((epochTime().int64 + 604800))

  echo "[DEBUG] Creating session for userId=", userId, " token=", result[0..10], "... expiresAt=", expiresAt
  discard dbInsertSession(userId, result, expiresAt)

# --- Jester Routes ---

routes:
  get "/":
    resp "Hello World!"

  post "/login":
    echo "[DEBUG] Login endpoint hit"
    let body = parseJson(request.body)
    let userOrEmail = body["username"].getStr
    let password = body["password"].getStr
    
    echo "[DEBUG] Login attempt for: ", userOrEmail
    
    # Basic validation
    if userOrEmail.len == 0 or password.len == 0:
      resp Http400, "Username and password required"
      return
    
    # Ensure database connection
    ensureDbConnection()
    
    # Check if user exists
    let user = dbGetUserByUsernameOrEmail(userOrEmail)
    if user.id == 0:
      echo "[DEBUG] User not found: ", userOrEmail
      resp Http401, "Invalid credentials"
      return
    
    # Verify password
    if not verifyPassword(password, user.passwordHash):
      echo "[DEBUG] Invalid password for user: ", userOrEmail
      resp Http401, "Invalid credentials"
      return
    
    echo "[DEBUG] Login successful for user: ", user.username
    
    # For now, just return success - we'll add session creation later
    resp Http200, "Login successful"

  # Dashboard API routes
  get "/dashboard/info":
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    echo "[DEBUG] Dashboard info - session token: ", if sessionToken.len > 0: sessionToken[0..10] & "..." else: "NONE"
    if sessionToken.len == 0:
      echo "[DEBUG] Dashboard info - no session token"
      resp Http401, "Not authenticated."
      return
    
    # Ensure database connection
    ensureDbConnection()
    
    let session = dbGetSessionByToken(sessionToken)
    echo "[DEBUG] Dashboard info - session lookup result: userId=", session.userId
    if session.userId == 0:
      echo "[DEBUG] Dashboard info - invalid session"
      resp Http401, "Invalid session."
      return
    
    let user = dbGetUserById(session.userId)
    echo "[DEBUG] Dashboard info - user lookup result: id=", user.id, " username=", user.username
    if user.id == 0:
      echo "[DEBUG] Dashboard info - user not found"
      resp Http401, "User not found."
      return
    
    resp Http200, $(%*{
      "username": user.username,
      "email": user.email,
      "last_login": user.lastLogin,
      "mfa_enabled": user.mfaEnabled
    })

  get "/dashboard/sessions":
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    if sessionToken.len == 0:
      resp Http401, "Not authenticated."
      return
    
    # Ensure database connection
    ensureDbConnection()
    
    let session = dbGetSessionByToken(sessionToken)
    if session.userId == 0:
      resp Http401, "Invalid session."
      return
    
    # Get list of active sessions for this user
    let sessions = dbListUserSessions(session.userId)
    var sessionList = %*[]
    
    for sess in sessions:
      sessionList.add(%*{
        "id": sess.id,
        "created": sess.createdAt,
        "ip": "127.0.0.1",  # Placeholder - we don't track IP in sessions table yet
        "current": sess.sessionToken == sessionToken
      })
    
    resp Http200, $sessionList

  post "/dashboard/sessions/@id/revoke":
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    if sessionToken.len == 0:
      resp Http401, "Not authenticated."
      return
    
    # Ensure database connection
    ensureDbConnection()
    
    let currentSession = dbGetSessionByToken(sessionToken)
    if currentSession.userId == 0:
      resp Http401, "Invalid session."
      return
    
    let sessionIdToRevoke = parseInt(@"id")
    echo "[DEBUG] Revoking session ", sessionIdToRevoke, " for user ", currentSession.userId
    echo "[DEBUG] Current session ID: ", currentSession.id, " token: ", currentSession.sessionToken[0..10], "..."
    
    # Prevent revoking current session
    if sessionIdToRevoke == currentSession.id:
      echo "[DEBUG] Cannot revoke current session"
      resp Http400, "Cannot revoke current session. Use logout instead."
      return
    
    if dbRevokeSession(sessionIdToRevoke):
      resp Http200, "Session revoked."
    else:
      resp Http500, "Failed to revoke session."

  # CSRF token route
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
      setCookie("csrf_token_value", newCsrfToken, expires = now() + 30.minutes)
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
  # initDdosProtector()  # Commented out as ddos_protector is not imported

  # Start Jester server
  echo "[MAIN] Starting Jester server..."
  runForever()
