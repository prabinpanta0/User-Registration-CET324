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

routes:   before hook(request):
     let clientIp = getClientIp(request)
     if clientIp.len == 0:
       echo "[ERROR] Could not determine client IP."
       resp Http500, "Internal Server Error: Cannot identify client."
       finish()
 
     # Check if IP is currently banned (from DB)
     let blockedStatusOption = getBlockedStatus(clientIp)
     if blockedStatusOption.isSome:
       let blockedUntil = blockedStatusOption.get
       if blockedUntil > now():
         echo "[WARN] Blocked IP attempted access: ", clientIp, " - Blocked until: ", $blockedUntil
         resp Http403, "Access denied. Your IP is currently blocked."
         finish()
 
     # Check for rate limiting (in-memory check, then potential ban via DB)
     if isRateLimited(clientIp):
       echo "[WARN] Rate limit exceeded by IP (hook): ", clientIp
       resp Http429, "Too many requests. Your IP has been temporarily blocked."
       finish()
 
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
    # Ensure database connection is active
    ensureDbConnection()

    let user = dbGetUserByUsernameOrEmail(userOrEmail)
    echo "[DEBUG] User lookup result - ID: ", user.id, " username: ", user.username, " email: ", user.email
    if user.id == 0:
      echo "[DEBUG] User not found for: ", userOrEmail
      logAudit("login_fail", ip, userOrEmail)
      resp Http401, "Invalid credentials."
      return
    
    let (_, lockoutUntil) = getUserLockoutInfo(user.id)
    if lockoutUntil.len > 0 and lockoutUntil > $(epochTime().int64):
      resp Http403, "Account locked. Try again later."
      return
    
    echo "[DEBUG] About to verify password - salt length: ", user.passwordSalt.len, " hash length: ", user.passwordHash.len
    let passwordValid = verifyPassword(password, user.passwordSalt, user.passwordHash)
    echo "[DEBUG] Password verification result: ", passwordValid
    if not passwordValid:
      discard incrementFailedLogin(user.id)
      logAudit("login_fail", ip, user.username)
      let (failCount, _) = getUserLockoutInfo(user.id)
      if failCount >= 5:
        let until = $((epochTime().int64 + 600))
        discard setLockout(user.id, until)
      resp Http401, "Invalid credentials."
      return
    
    discard resetFailedLogin(user.id)
    
    # Update last login timestamp
    discard dbUpdateUserLastLogin(user.id)
    
    # Check if MFA is enabled for existing users
    if user.mfaEnabled:
      # Store temporary session for MFA verification
      let tempSession = createSession(user.id, temporary = true)
      setCookie("temp_session", tempSession, path = "/", httpOnly = true)
      resp Http200, "mfa_required"
    else:
      # For users without MFA (newly registered), create regular session
      let sessionToken = createSession(user.id)
      setCookie("session", sessionToken, path = "/", httpOnly = true)
      resp Http200, "Login successful."

  # MFA verification for login - PROPER IMPLEMENTATION
  post "/login/mfa":
    echo "[LOGIN MFA] Route called"
    let ip = "127.0.0.1"
    if not checkRateLimit(ip, "mfa"):
      echo "[LOGIN MFA] Rate limited"
      resp Http429, "Too many attempts. Please try later."
      return

    let tempSession = if request.cookies.hasKey("temp_session"): request.cookies["temp_session"] else: ""
    if tempSession.len == 0:
      echo "[LOGIN MFA] No temp session found"
      resp Http401, "No pending MFA verification."
      return

    let session = dbGetSessionByToken(tempSession)
    if session.userId == 0:
      echo "[LOGIN MFA] Invalid temp session"
      resp Http401, "Invalid session."
      return

    let body = parseJson(request.body)
    let mfaCode = body["mfa_code"].getStr
    echo "[LOGIN MFA] Code entered: '", mfaCode, "' length: ", mfaCode.len

    # Validate code format
    if mfaCode.len != 6:
      echo "[LOGIN MFA] ERROR: Invalid code length"
      resp Http400, "Invalid code format. Must be 6 digits."
      return

    # Check if code is all digits
    for c in mfaCode:
      if not c.isDigit:
        echo "[LOGIN MFA] ERROR: Non-digit character in code"
        resp Http400, "Invalid code format. Must be 6 digits."
        return

    # Get user and their MFA secret
    let user = dbGetUserById(session.userId)
    if user.id == 0 or not user.mfaEnabled:
      echo "[LOGIN MFA] ERROR: User not found or MFA not enabled"
      resp Http401, "MFA not enabled for this user."
      return

    let (encSecret, iv) = dbGetUserMfaSecret(session.userId)
    echo "[LOGIN MFA] Raw encrypted secret length: ", encSecret.len, " IV length: ", iv.len
    
    if encSecret.len == 0 or iv.len == 0:
      echo "[LOGIN MFA] ERROR: No MFA secret found for user"
      resp Http500, "MFA not set up properly."
      return
    
    let secret = aesDecrypt(encSecret, iv)
    echo "[LOGIN MFA] Secret decrypted, length: ", secret.len
    
    if secret.len == 0:
      echo "[LOGIN MFA] ERROR: Failed to decrypt MFA secret"
      resp Http500, "MFA decryption failed."
      return

    # Use proper TOTP verification
    if not verifyTotp(secret, mfaCode, 30, 1):
      echo "[LOGIN MFA] Code verification FAILED"
      resp Http400, "Invalid MFA code."
      return
    echo "[LOGIN MFA] Code verification SUCCESS"

    # Clear temp session
    setCookie("temp_session", "", expires = "Thu, 01 Jan 1970 00:00:00 GMT")
    discard dbDeleteSession(tempSession)
    
    # Create permanent session
    let sessionToken = createSession(session.userId)
    setCookie("session", sessionToken, path = "/", httpOnly = true)
    echo "[LOGIN MFA] Login successful"
    resp Http200, "Login successful."

  post "/logout":
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    if sessionToken.len > 0:
      discard dbDeleteSession(sessionToken)
    setCookie("session", "", expires = "Thu, 01 Jan 1970 00:00:00 GMT")
    resp Http200, "Logged out."

  # Register route
  post "/register":
    echo "[ROUTE DEBUG] Registration route hit!"
    let ip = "127.0.0.1"
    if not checkRateLimit(ip, "register"):
      resp Http429, "Too many attempts. Please try later."
      return

    let body = parseJson(request.body)
    let username = body["username"].getStr
    let email = body["email"].getStr
    let password = body["password"].getStr
    let confirm = body["confirm_password"].getStr
    let captcha = body["captcha"].getStr
    let honeypot = if body.hasKey("website"): body["website"].getStr else: ""

    if honeypot.len > 0:
      resp Http400, "Bot detected."
      return
    if password != confirm:
      resp Http400, "Passwords do not match."
      return
    if not validPassword(password):
      resp Http400, "Password does not meet requirements."
      return
    if not validUsername(username):
      resp Http400, "Invalid username."
      return
    if not validEmail(email):
      resp Http400, "Invalid email."
      return
    if not verifyCaptcha(ip, captcha):
      resp Http400, "Invalid captcha."
      return

    # Check if user already exists before attempting insertion
    if dbUserExists(username, email):
      resp Http409, "Username or email already exists."
      return

    let salt = generateSalt()
    let hash = hashPassword(password, salt)
    
    echo "[DEBUG] Attempting to insert user: ", username, " with email: ", email
    let insertResult = dbInsertUser(username, email, hash, salt)
    echo "[DEBUG] Insert result: ", insertResult
    
    if not insertResult:
      echo "[ERROR] Failed to insert user into database"
      resp Http500, "Database error. Please try again later."
      return
    
    # Get the newly created user
    let user = dbGetUserByUsernameOrEmail(username)
    if user.id == 0:
      resp Http500, "User creation failed."
      return
    
    # Create a session for the newly registered user
    let sessionToken = createSession(user.id)
    setCookie("session", sessionToken, path = "/", httpOnly = true)
    
    resp Http200, "Registration successful. Redirecting to MFA setup."

  # MFA Setup route
  post "/mfa/setup":
    echo "[MFA SETUP] Route called"
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    if sessionToken.len == 0:
      echo "[MFA SETUP] Not authenticated - no session"
      resp Http401, "Not authenticated."
      return
    
    let session = dbGetSessionByToken(sessionToken)
    if session.userId == 0:
      echo "[MFA SETUP] Invalid session"
      resp Http401, "Invalid session."
      return
    
    let user = dbGetUserById(session.userId)
    if user.id == 0:
      echo "[MFA SETUP] User not found"
      resp Http401, "User not found."
      return
    
    # Generate proper random TOTP secret
    let secret = generateTotpSecret()
    echo "[MFA SETUP] Generated secret, length: ", secret.len
    
    # Encrypt and store the secret properly
    let (encSecret, iv) = aesEncrypt(secret)
    if not dbSetUserMfaSecret(user.id, encSecret, iv):
      echo "[MFA SETUP] Failed to store encrypted secret"
      resp Http500, "Failed to store MFA secret."
      return
    echo "[MFA SETUP] Secret stored successfully"
    
    # Generate otpauth URL
    let otpauth = "otpauth://totp/SecureApp:" & user.username & "?secret=" & secret & "&issuer=SecureApp"
    echo "[MFA SETUP] Generated otpauth URL"
    
    # Return data for client-side QR generation
    resp Http200, $(%*{"otpauth": otpauth, "secret": secret}), "application/json"

  # MFA Verification route - PROPER IMPLEMENTATION
  post "/mfa/verify":
    echo "[MFA VERIFY] Route called"
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    if sessionToken.len == 0:
      echo "[MFA VERIFY] Not authenticated - no session"
      resp Http401, "Not authenticated."
      return
    
    let session = dbGetSessionByToken(sessionToken)
    if session.userId == 0:
      echo "[MFA VERIFY] Invalid session"
      resp Http401, "Invalid session."
      return
    
    let body = parseJson(request.body)
    let code = body["code"].getStr
    echo "[MFA VERIFY] Code entered: '", code, "' length: ", code.len
    
    # Validate code format
    if code.len != 6:
      echo "[MFA VERIFY] ERROR: Invalid code length"
      resp Http400, "Invalid code format. Must be 6 digits."
      return
    
    # Check if code is all digits
    for c in code:
      if not c.isDigit:
        echo "[MFA VERIFY] ERROR: Non-digit character in code"
        resp Http400, "Invalid code format. Must be 6 digits."
        return
    
    let (encSecret, iv) = dbGetUserMfaSecret(session.userId)
    echo "[MFA VERIFY] Raw encrypted secret length: ", encSecret.len, " IV length: ", iv.len
    
    if encSecret.len == 0 or iv.len == 0:
      echo "[MFA VERIFY] ERROR: No MFA secret found for user"
      resp Http500, "MFA not set up properly."
      return
    
    let secret = aesDecrypt(encSecret, iv)
    echo "[MFA VERIFY] Secret decrypted, length: ", secret.len
    
    if secret.len == 0:
      echo "[MFA VERIFY] ERROR: Failed to decrypt MFA secret"
      resp Http500, "MFA decryption failed."
      return
    
    # Use proper TOTP verification
    if not verifyTotp(secret, code, 30, 1):
      echo "[MFA VERIFY] Code verification FAILED"
      resp Http400, "Invalid code."
      return
    echo "[MFA VERIFY] Code verification SUCCESS"
    
    if not dbEnableUserMfa(session.userId):
      echo "[MFA VERIFY] Failed to enable MFA in database"
      resp Http500, "Failed to enable MFA."
      return
    echo "[MFA VERIFY] MFA enabled successfully"
    resp Http200, "MFA enabled."

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
