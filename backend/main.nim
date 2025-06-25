import os
import utils/env # Import env utils first
loadEnvFile()     # Load .env file immediately

import jester
import db/db
import db/models
import crypto/password
import crypto/aes
import utils/rate_limit
import utils/csrf_validator
import utils/ddos_protector
import utils/email_sender
import utils/jwt_utils
import utils/totp_utils
import utils/mfa_recovery_utils
import times, strutils, json, random, options, sequtils
import nimcrypto/sysrand as cryptoRandom # For cryptographically secure random bytes
import nimcrypto # For hmac_sha1
import postgres as pg # For health check constants

# --- Helper Procedures ---

# Rate Limiting Configuration for Registration
const registerAttemptConfig = RateLimitConfig(
  routeIdentifier: "register_attempt",
  maxAttemptsShortTerm: 10,       # Max 10 registration attempts
  windowSecShortTerm: 3600,     # within a 1-hour window
  blockDurationSecLongTerm: 86400 # Long-term DB block for 24 hours if limit exceeded
)

# Rate Limiting Configurations for MFA
const mfaSetupConfig = RateLimitConfig(
  routeIdentifier: "mfa_initial_setup",
  maxAttemptsShortTerm: 3,        # Max 3 setup attempts (generation of new secret)
  windowSecShortTerm: 600,      # within a 10-minute window by an authenticated user
  blockDurationSecLongTerm: 3600  # Long-term DB block for 1 hour if limit exceeded
)

const mfaInitialVerifyConfig = RateLimitConfig(
  routeIdentifier: "mfa_initial_verify",
  maxAttemptsShortTerm: 5,        # Max 5 verification attempts for the newly generated secret
  windowSecShortTerm: 120,      # within a 2-minute window
  blockDurationSecLongTerm: 1800  # Long-term DB block for 30 minutes if limit exceeded
)

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

  echo "[DEBUG] Creating session for userId=", userId, " token=", if result.len > 10: "[REDACTED]" else: "[REDACTED]", " expiresAt=", expiresAt
  discard dbInsertSession(userId, result, expiresAt)

proc getCurrentUser(request: Request): User =
  let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
  echo "[DEBUG] getCurrentUser - session token: ", if sessionToken.len > 0: sessionToken[0..10] & "..." else: "NONE"
  echo "[DEBUG] getCurrentUser - all cookies: ", request.cookies
  if sessionToken.len == 0:
    echo "[DEBUG] getCurrentUser - no session token found"
    return User()  # Return empty user if no session
  
  # Ensure database connection
  ensureDbConnection()
  
  let session = dbGetSessionByToken(sessionToken)
  echo "[DEBUG] getCurrentUser - session lookup result: userId=", session.userId, " token=", if session.sessionToken.len > 0: session.sessionToken[0..10] & "..." else: "NONE"
  if session.userId == 0:
    echo "[DEBUG] getCurrentUser - invalid session"
    return User()  # Return empty user if invalid session
  
  let user = dbGetUserById(session.userId)
  echo "[DEBUG] getCurrentUser - user lookup result: id=", user.id, " username=", user.username
  
  # If user doesn't exist but session does, clean up the orphaned session
  if user.id == 0 and session.userId != 0:
    echo "[DEBUG] getCurrentUser - cleaning up orphaned session for deleted user: ", session.userId
    discard dbDeleteSession(sessionToken)
    return User()
  
  return user

# --- Jester Routes ---

routes:
  get "/":
    resp "Hello World!"

  # Health check endpoint
  get "/health":
    try:
      # Ensure we have a database connection
      ensureDbConnection()
      if checkDbConnection():
        resp Http200, $(%*{"status": "healthy", "database": "connected", "timestamp": $now()})
      else:
        resp Http503, $(%*{"status": "unhealthy", "database": "connection_failed", "timestamp": $now()})
    except Exception as e:
      echo "[HEALTH ERROR] Exception in health check: ", e.msg
      resp Http503, $(%*{"status": "unhealthy", "database": "error", "error": e.msg, "timestamp": $now()})

  # API info endpoint
  get "/api/info":
    resp Http200, $(%*{
      "name": "ACS Assignment Backend",
      "version": "1.0.0",
      "status": "running",
      "features": ["authentication", "mfa", "email_verification", "session_management"],
      "timestamp": $now()
    })

  post "/login":
    echo "[DEBUG] Login endpoint hit"
    
    # CSRF Check (pre-session)
    if not verifyCsrf(request, isPreSession = true):
      resp Http403, "CSRF token validation failed."
      return

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
    
    # Check if email is verified
    if not user.isVerified:
      echo "[DEBUG] User email not verified: ", userOrEmail
      resp Http401, "Please verify your email address before logging in."
      return
    
    # Verify password
    if not verifyPassword(password, user.passwordHash):
      echo "[DEBUG] Invalid password for user: ", userOrEmail
      resp Http401, "Invalid credentials"
      return
    
    echo "[DEBUG] Login successful for user: ", user.username
    echo "[DEBUG] User MFA status: enabled=", user.mfaEnabled
    
    # Check if user has MFA enabled
    if user.mfaEnabled:
      # Create temporary session for MFA verification
      let tempSession = createSession(user.id, temporary = true)
      # Set temp_session cookie
      setCookie("temp_session", tempSession, expires = now() + 10.minutes, path = "/", httpOnly = true)
      resp Http200, $(%*{"status": "mfa_required"})
      return
    else:
      # Create regular session and redirect to MFA setup or dashboard
      let session = createSession(user.id, temporary = false)
      # Set session cookie
      setCookie("session", session, expires = now() + 7.days, path = "/", httpOnly = true)
      
      # Clear the CSRF double-submit cookie after final login
      setCookie("csrf_token_value", "", expires = now() - 1.days)
      
      # Update last login time
      discard dbUpdateUserLastLogin(user.id)
      
      # Return success with redirect information
      resp Http200, $(%*{"status": "success", "redirect": "/mfa/setup"})

    return

  # Dashboard API routes
  get "/dashboard/info":
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    if sessionToken.len == 0:
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
    
    # CSRF Check (post-session)
    if not verifyCsrf(request, isPreSession = false):
      resp Http403, "CSRF token validation failed."
      return
    
    # Ensure database connection
    ensureDbConnection()
    
    let currentSession = dbGetSessionByToken(sessionToken)
    if currentSession.userId == 0:
      resp Http401, "Invalid session."
      return
    
    let sessionIdToRevoke = parseInt(@"id")
    echo "[DEBUG] Revoking session ", sessionIdToRevoke, " for user ", currentSession.userId
    echo "[DEBUG] Current session ID: ", currentSession.id, " token: [REDACTED]" # Security: Never log session tokens
    
    # Prevent revoking current session
    if sessionIdToRevoke == currentSession.id:
      echo "[DEBUG] Cannot revoke current session"
      resp Http400, "Cannot revoke current session. Use logout instead."
      return
    
    if dbRevokeSession(sessionIdToRevoke):
      resp Http200, "Session revoked."
    else:
      resp Http500, "Failed to revoke session."

  # MFA Recovery Codes Status endpoint
  get "/mfa/recovery-codes/status":
    # Wrap in try to handle errors gracefully
    try:
      let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
      if sessionToken.len == 0:
        resp Http401, "Not authenticated."
        return

      ensureDbConnection()

      let currentSession = dbGetSessionByToken(sessionToken)
      if currentSession.userId == 0:
        resp Http401, "Invalid session."
        return

      let user = dbGetUserById(currentSession.userId)
      if user.id == 0:
        resp Http401, "User not found."
        return

      if not user.mfaEnabled:
        resp Http200, $(%*{"has_codes": false, "count": 0, "mfa_enabled": false}), "application/json"
        return

      let hashedCodes = dbGetUserRecoveryCodes(user.id)
      let count = hashedCodes.len

      resp Http200, $(%*{
        "has_codes": count > 0,
        "count": count,
        "mfa_enabled": true
      }), "application/json"
    except Exception as e:
      echo "[ERROR] Exception in /mfa/recovery-codes/status: ", e.msg
      resp Http500, $(%*{"error": "Internal Server Error"}), "application/json"

  # MFA Recovery Codes Regenerate endpoint
  post "/mfa/recovery-codes/regenerate":
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    if sessionToken.len == 0:
      resp Http401, "Not authenticated."
      return

    # CSRF Check (session-bound)
    if not verifyCsrf(request):
      resp Http403, "CSRF token validation failed."
      return

    # Ensure database connection
    ensureDbConnection()
    
    let currentSession = dbGetSessionByToken(sessionToken)
    if currentSession.userId == 0:
      resp Http401, "Invalid session."
      return
    
    let user = dbGetUserById(currentSession.userId)
    if user.id == 0:
      resp Http401, "User not found."
      return

    if not user.mfaEnabled:
      resp Http400, "MFA is not enabled."
      return

    # Generate new recovery codes
    let (newCodes, hashedCodes) = generateRecoveryCodes()
    
    if dbSetUserRecoveryCodes(user.id, hashedCodes):
      resp Http200, $(%*{"status": "success", "recovery_codes": newCodes}), "application/json"
    else:
      resp Http500, "Failed to store new recovery codes."

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

    if isExistingSession:
      # For authenticated users, return existing CSRF token if present, otherwise generate new one
      if userSession.csrfToken.len > 0:
        echo "[CSRF] Returning existing CSRF token in session for user ID: ", userSession.userId
        resp Http200, $(%*{"csrf_token": userSession.csrfToken}), "application/json"
      else:
        # No CSRF token in session yet, generate one
        let newCsrfToken = generateSecureRandomToken()
        if dbUpdateSessionCsrfToken(userSession.sessionToken, newCsrfToken):
          echo "[CSRF] Created new CSRF token in session for user ID: ", userSession.userId
          resp Http200, $(%*{"csrf_token": newCsrfToken}), "application/json"
        else:
          echo "[CSRF ERROR] Failed to update CSRF token in session database for user ID: ", userSession.userId
          resp Http500, "Error generating CSRF token (session update failed)."
    else:
      # For non-authenticated users, use double submit cookie pattern
      let newCsrfToken = generateSecureRandomToken()
      # Set path to "/" so cookie is available to all routes
      setCookie("csrf_token_value", newCsrfToken, expires = now() + 30.minutes, path = "/")
      echo "[CSRF] Issued CSRF token via double submit cookie method."
      resp Http200, $(%*{"csrf_token": newCsrfToken}), "application/json"

  # Logout endpoint
  post "/logout":
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    if sessionToken.len == 0:
      resp Http401, "Not authenticated."
      return
    
    # CSRF Check (session-bound)
    if not verifyCsrf(request):
      resp Http403, "CSRF token validation failed."
      return
    
    # Ensure database connection
    ensureDbConnection()
    
    # Delete the session from database
    if dbDeleteSession(sessionToken):
      # Clear the session cookie
      setCookie("session", "", expires = now() - 1.days, path = "/")
      echo "[AUTH] User logged out successfully"
      resp Http200, "Logged out successfully."
    else:
      echo "[AUTH ERROR] Failed to delete session during logout"
      resp Http500, "Failed to logout."

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

  post "/register":
    let ip = getClientIp(request)
    if not isRequestAllowed(ip, registerAttemptConfig):
      resp Http429, "Too many registration attempts. Please try later."
      return

    # CSRF Check (pre-session)
    if not verifyCsrf(request, isPreSession = true):
      resp Http403, "CSRF token validation failed."
      return
    # Clear the double submit cookie after successful use
    setCookie("csrf_token_value", "", expires = now() - 1.days)

    let body = parseJson(request.body)
    let username = body["username"].getStr
    let email = body["email"].getStr
    let password = body["password"].getStr
    let confirm = body["confirm_password"].getStr
    # Ensure the frontend sends the hCaptcha token as "h-captcha-response" or "captcha"
    let captchaToken = if body.hasKey("h-captcha-response"): body["h-captcha-response"].getStr
                       elif body.hasKey("captcha"): body["captcha"].getStr
                       else: ""
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

    # For now, skip captcha verification to test basic functionality
    # TODO: Re-enable captcha verification
    # if not await verifyCaptcha(captchaToken, ip):
    #   resp Http400, "Invalid CAPTCHA. Please try again."
    #   return

    # Check if password is pwned
    # For now, skip HIBP check to test basic functionality
    # TODO: Re-enable HIBP check
    # if await isPasswordPwned(password):
    #   resp Http400, "This password has been exposed in data breaches. Please choose a different password."
    #   return

    # Argon2id handles salt internally; hashPassword now only takes the password.
    let hash = hashPassword(password)
    
    echo "[DEBUG] Attempting to insert user: ", username, " with email: ", email
    # Pass an empty string for salt, as it's now part of the hash.
    let insertResult = dbInsertUser(username, email, hash, "")
    echo "[DEBUG] Insert result: ", insertResult
    
    if not insertResult:
      echo "[ERROR] Failed to insert user into database"
      resp Http500, "User registration failed. Please try again."
      return
    
    # User inserted successfully - send verification email with code
    let user = dbGetUserByUsernameOrEmail(username)
    if user.id == 0:
      resp Http500, "User creation failed."
      return
    
    # Generate 6-digit verification code
    randomize()
    var verificationCode = ""
    for i in 0..<6:
      verificationCode.add char(ord('0') + rand(9))
    
    # Store verification code in database
    if not dbCreateVerificationCode(user.id, verificationCode, 24):
      echo "[ERROR] Failed to create verification code for user ", user.id
      resp Http500, "Failed to create verification code."
      return
    
    # Send verification email with code
    let emailSubject = "Your Email Verification Code - ACS Assignment"
    let emailBody = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Verification</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4F46E5; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .code { font-size: 24px; font-weight: bold; background-color: #e5e7eb; padding: 15px; text-align: center; border-radius: 5px; margin: 20px 0; }
        .footer { padding: 10px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Email Verification</h1>
        </div>
        <div class="content">
            <h2>Hello!</h2>
            <p>Thank you for registering with ACS Assignment. To complete your registration, please use the verification code below:</p>
            <div class="code">""" & verificationCode & """</div>
            <p><strong>Important:</strong></p>
            <ul>
                <li>This code will expire in 24 hours</li>
                <li>Enter this code on the verification page to activate your account</li>
                <li>If you didn't request this registration, please ignore this email</li>
            </ul>
        </div>
        <div class="footer">
            <p>This is an automated email from ACS Assignment. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""
    
    echo "[INFO] Sending verification email to: ", user.email
    
    # Send the email with HTML format
    let emailResult = await sendEmail(user.email, emailSubject, emailBody, isHtml = true)
    if not emailResult:
      echo "[ERROR] Failed to send verification email to: ", user.email
      # Don't fail registration even if email fails - user can still verify manually
    else:
      echo "[INFO] Verification email sent successfully to: ", user.email
    
    resp Http200, "Registration successful. Please check your email for a verification code."

  # Email verification with code
  post "/verify-email-code":
    # CSRF Check (pre-session)
    if not verifyCsrf(request, isPreSession = true):
      resp Http403, "CSRF token validation failed."
      return
    setCookie("csrf_token_value", "", expires = now() - 1.days)

    # Get code from either JSON body or form parameters
    var code = ""
    var contentType = ""
    try:
      contentType = request.headers["Content-Type"]
    except KeyError:
      contentType = ""
    
    if contentType.contains("application/json"):
      # JSON request
      let body = parseJson(request.body)
      if body.hasKey("code"):
        code = body["code"].getStr()
    else:
      # Form data request
      code = request.params.getOrDefault("code", "")

    if code.len != 6:
      resp Http400, "Invalid verification code format. Code must be 6 digits."
      return

    # Validate that code contains only digits
    for c in code:
      if not c.isDigit:
        resp Http400, "Invalid verification code format. Code must contain only digits."
        return

    ensureDbConnection()
    
    # Find user by verification code
    let userIdOpt = dbGetUserIdByVerificationCode(code)
    if userIdOpt.isNone():
      resp Http400, "Invalid or expired verification code."
      return

    let userId = userIdOpt.get()
    let user = dbGetUserById(userId)
    if user.id == 0:
      resp Http400, "User not found."
      return

    if user.isVerified:
      resp Http200, "Email is already verified."
      return

    # Verify the code and mark as used
    if dbVerifyEmailCode(userId, code):
      if dbSetUserVerified(userId):
        # Automatically log in the user after email verification
        let session = createSession(userId, temporary = false)
        setCookie("session", session, expires = now() + 7.days, path = "/", httpOnly = true)
        
        # Update last login time
        discard dbUpdateUserLastLogin(userId)
        
        resp Http200, $(%*{"status": "success", "message": "Email verified successfully. Setting up MFA...", "redirect": "/mfa/setup"})
      else:
        echo "[ERROR] Failed to set user as verified after code validation for user ID: ", userId
        resp Http500, "Failed to complete verification. Please try again."
    else:
      resp Http400, "Invalid or expired verification code."

  # Email verification route (legacy - for old links)
  get "/verify-email":
    let token = request.params.getOrDefault("token", "")
    if token.len == 0:
      # Redirect to a verification page with error message
      redirect("/email-verification?error=missing_token")
      return

    let claimsOption = validateJwtToken(token)
    if claimsOption.isNone():
      redirect("/email-verification?error=invalid_token")
      return

    let claims = claimsOption.get()
    if not claims.hasKey("user_id") or not claims.hasKey("type") or 
       claims["type"].getStr() != "email_verification":
      redirect("/email-verification?error=invalid_token")
      return

    let userId = claims["user_id"].getInt()
    if userId == 0:
      redirect("/email-verification?error=invalid_token")
      return

    ensureDbConnection()
    let user = dbGetUserById(userId)
    if user.id == 0:
      redirect("/email-verification?error=user_not_found")
      return

    if user.isVerified:
      redirect("/email-verification?success=already_verified")
      return

    if dbSetUserVerified(userId):
      redirect("/email-verification?success=verified&next=mfa_setup")
    else:
      redirect("/email-verification?error=verification_failed")

  # Email verification page route
  get "/email-verification":
    resp readFile("frontend/views/email_verification.lp")

  # MFA Setup GET Route (for initial page load)
  get "/mfa/setup":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    let ip = getClientIp(request)
    if not isRequestAllowed(ip, mfaSetupConfig):
      resp Http429, "Too many MFA setup attempts. Please try later."
      return

    let secret = generateTotpSecret()
    let (encSecret, iv) = aesEncrypt(secret)
    if not dbSetUserMfaSecret(user.id, encSecret, iv):
      resp Http500, "Failed to store MFA secret."
      return

    let otpauth = "otpauth://totp/SecureApp:" & user.username & "?secret=" & secret & "&issuer=SecureApp"
    let response = %*{
      "otpauth": otpauth,
      "secret": secret
    }
    # Note: Secret is included for manual entry. It's already in the QR code anyway.
    resp Http200, $response

  # MFA Setup Route
  post "/mfa/setup":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    # CSRF Check (session-bound)
    if not verifyCsrf(request):
      resp Http403, "CSRF token validation failed."
      return

    let ip = getClientIp(request)
    if not isRequestAllowed(ip, mfaSetupConfig):
      resp Http429, "Too many MFA setup attempts. Please try later."
      return

    let secret = generateTotpSecret()
    let (encSecret, iv) = aesEncrypt(secret)
    if not dbSetUserMfaSecret(user.id, encSecret, iv):
      resp Http500, "Failed to store MFA secret."
      return

    let otpauth = "otpauth://totp/SecureApp:" & user.username & "?secret=" & secret & "&issuer=SecureApp"
    let response = %*{
      "otpauth": otpauth,
      "secret": secret
    }
    # Note: Secret is included for manual entry. It's already in the QR code anyway.
    resp Http200, $response

  # MFA Verify Route  
  post "/mfa/verify":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    # CSRF Check (session-bound)
    if not verifyCsrf(request):
      resp Http403, "CSRF token validation failed."
      return

    let body = parseJson(request.body)
    let code = body["code"].getStr

    let ip = getClientIp(request)
    if not isRequestAllowed(ip, mfaInitialVerifyConfig):
      resp Http429, "Too many MFA verification attempts. Please try later."
      return

    # Get encrypted secret from database
    let (encryptedSecret, iv) = dbGetUserMfaSecret(user.id)
    if encryptedSecret.len == 0:
      resp Http400, "No MFA secret found. Please setup MFA first."
      return

    # Decrypt the secret
    let secret = aesDecrypt(encryptedSecret, iv)
    if secret.len == 0:
      resp Http500, "Failed to decrypt MFA secret."
      return

    # Verify TOTP code
    if not verifyTotp(secret, code):
      resp Http400, "Invalid MFA code."
      return

    # Enable MFA for user and generate recovery codes
    if not dbEnableUserMfa(user.id):
      resp Http500, "Failed to enable MFA."
      return

    # Generate and store recovery codes
    randomize() # Ensure random is seeded before generating codes
    let (plaintextCodes, hashedCodes) = generateRecoveryCodes()
    if not dbSetUserRecoveryCodes(user.id, hashedCodes):
      resp Http200, $(%*{"status": "mfa_enabled", "message": "MFA enabled, but recovery code generation failed. Please contact support."})
      return

    let response = %*{
      "status": "success",
      "recoveryCodes": plaintextCodes
    }
    resp Http200, $response

  # MFA Login Route (for existing users with MFA enabled)
  post "/login/mfa":
    let tempSessionToken = if request.cookies.hasKey("temp_session"): request.cookies["temp_session"] else: ""
    if tempSessionToken.len == 0:
      resp Http401, "No temporary session found."
      return

    # No CSRF check here; temp_session token secures this route

    # Ensure database connection
    ensureDbConnection()
    
    let tempSession = dbGetSessionByToken(tempSessionToken)
    if tempSession.userId == 0:
      resp Http401, "Invalid temporary session."
      return

    let user = dbGetUserById(tempSession.userId)
    if user.id == 0:
      resp Http401, "User not found."
      return

    if not user.mfaEnabled:
      resp Http400, "MFA is not enabled for this account."
      return

    let body = parseJson(request.body)
    # Support both 'mfa_code' and 'mfa_recovery_code'
    var code = ""
    if body.hasKey("mfa_code"):
      code = body["mfa_code"].getStr()
    elif body.hasKey("mfa_recovery_code"):
      code = body["mfa_recovery_code"].getStr()
    else:
      resp Http400, "MFA code is required."
      return
    # Trim whitespace
    code = code.strip()

    let ip = getClientIp(request)
    if not isRequestAllowed(ip, mfaInitialVerifyConfig):
      resp Http429, "Too many MFA verification attempts. Please try later."
      return

    # Get encrypted secret from database
    let (encryptedSecret, iv) = dbGetUserMfaSecret(user.id)
    if encryptedSecret.len == 0:
      resp Http400, "No MFA secret found."
      return

    # Decrypt the secret
    let secret = aesDecrypt(encryptedSecret, iv)
    if secret.len == 0:
      resp Http500, "Failed to decrypt MFA secret."
      return

    # Verify TOTP code
    if not verifyTotp(secret, code):
      resp Http400, "Invalid MFA code."
      return

    # MFA verification successful - create regular session and delete temporary session
    let regularSession = createSession(user.id, temporary = false)
    discard dbDeleteSession(tempSessionToken)
    # Clear temp_session and set session cookie
    setCookie("temp_session", "", expires = now() - 1.days, path = "/")
    setCookie("session", regularSession, expires = now() + 7.days, path = "/", httpOnly = true)
    
    # Update last login time
    discard dbUpdateUserLastLogin(user.id)
    
    echo "[DEBUG] MFA login successful for user: ", user.username
    resp Http200, $(%*{"status": "success", "redirect": "/dashboard"})

  # Session check endpoint for frontend authentication validation
  get "/session-check":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, $(%*{"authenticated": false})
      return
    
    resp Http200, $(%*{
      "authenticated": true,
      "user_id": user.id,
      "username": user.username,
      "mfa_enabled": user.mfaEnabled
    })

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
    
    # Verify connection immediately
    if checkDbConnection():
      echo "[MAIN] Database connection verified successfully"
    else:
      echo "[MAIN ERROR] Database connection verification failed"
      quit(1)
  except Exception as e:
    echo "[MAIN ERROR] Database connection failed: ", e.msg
    quit(1)

  # Initialize DDoS Protector
  initDdosProtector()

  # Start Jester server
  echo "[MAIN] Starting Jester server on port ", portNum, "..."
  
  # Use the traditional jester approach
  runForever()
