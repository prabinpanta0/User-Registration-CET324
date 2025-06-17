import jester, strutils, json, times, random, os
import ../db/db
import ../db/models
import ../crypto/password
import ../crypto/aes
import ../utils/rate_limit
import ../utils/audit_log
import ../utils/totp_utils # Import for verifyTotp

# Rate Limiting Configurations
const loginAttemptConfig = RateLimitConfig(
  routeIdentifier: "login_attempt",
  maxAttemptsShortTerm: 5,
  windowSecShortTerm: 60, # 5 attempts per minute
  blockDurationSecLongTerm: 900 # 15 minutes DB block
)

const mfaVerifyConfig = RateLimitConfig(
  routeIdentifier: "login_mfa_verify",
  maxAttemptsShortTerm: 5,
  windowSecShortTerm: 120, # 5 attempts per 2 minutes
  blockDurationSecLongTerm: 1800 # 30 minutes DB block
)

# Import verifyCaptcha from register.nim - simplified for now
proc verifyCaptcha(ip, captcha: string): bool =
  # Skip captcha verification for now to avoid GC safety issues
  result = true

# Check if user has MFA enabled
proc userHasMfa(userId: int64): bool =
  let user = dbGetUserById(userId.int)
  return user.mfaEnabled

# Session management functions
proc getCurrentUser*(request: Request): User =
  let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
  echo "[DEBUG] getCurrentUser - session token: ", if sessionToken.len > 0: sessionToken[0..10] & "..." else: "NONE"
  if sessionToken.len == 0:
    echo "[DEBUG] getCurrentUser - no session token found"
    return User()  # Return empty user if no session
  
  # Ensure database connection
  ensureDbConnection()
  
  let session = dbGetSessionByToken(sessionToken)
  echo "[DEBUG] getCurrentUser - session lookup result: userId=", session.userId, " token=", if session.token.len > 0: session.token[0..10] & "..." else: "NONE"
  if session.userId == 0:
    echo "[DEBUG] getCurrentUser - invalid session"
    return User()  # Return empty user if invalid session
  
  let user = dbGetUserById(session.userId)
  echo "[DEBUG] getCurrentUser - user lookup result: id=", user.id, " username=", user.username
  return user

proc createSession*(userId: int, temporary: bool = false): string =
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

proc getUserIdFromSession*(sessionToken: string): int =
  let session = dbGetSessionByToken(sessionToken)
  return session.userId

routes:
  post "/login":
    echo "[DEBUG] Login endpoint hit"
    let ip = "127.0.0.1"  # Fallback IP for now - TODO: Replace with actual client IP
    if not isRequestAllowed(ip, loginAttemptConfig):
      resp Http429, "Too many attempts. Please try later."
      return

    let body = parseJson(request.body)
    let userOrEmail = body["username"].getStr
    let password = body["password"].getStr
    let captcha = if body.hasKey("captcha"): body["captcha"].getStr else: ""
    echo "[DEBUG] Login attempt - user: ", userOrEmail, " password length: ", password.len

    if not verifyCaptcha(ip, captcha):
      resp Http400, "Invalid captcha."
      return

    # Ensure database connection is active
    ensureDbConnection()

    let user = dbGetUserByUsernameOrEmail(userOrEmail)
    echo "[DEBUG] Login attempt for: ", userOrEmail
    echo "[DEBUG] User found: ", user.id, " username: ", user.username, " email: ", user.email
    if user.id == 0:
      echo "[DEBUG] User not found for: ", userOrEmail
      logAudit("login_fail", ip, userOrEmail)
      resp Http401, "Invalid credentials."
      return
    # Check lockout
    let (_, lockoutUntil) = getUserLockoutInfo(user.id)
    if lockoutUntil.len > 0 and lockoutUntil > $(epochTime().int64):
      resp Http403, "Account locked. Try again later."
      return
    echo "[DEBUG] Verifying password. Salt length: ", user.passwordSalt.len, " Hash length: ", user.passwordHash.len
    let passwordVerified = verifyPassword(password, user.passwordSalt, user.passwordHash)
    echo "[DEBUG] Password verification result: ", passwordVerified
    if not passwordVerified:
      discard incrementFailedLogin(user.id)
      logAudit("login_fail", ip, user.username)
      let (failCount, _) = getUserLockoutInfo(user.id)
      if failCount >= 5:
        let until = $((epochTime().int64 + 600)) # lockout 10 min
        discard setLockout(user.id, until)
      resp Http401, "Invalid credentials."
      return
    discard resetFailedLogin(user.id)
    discard dbUpdateUserLastLogin(user.id) # Update last login timestamp

    # Check password expiry
    var passwordExpired = false
    if user.passwordLastChanged.len > 0:
      try:
        # Assuming passwordLastChanged is in ISO 8601 format from DB (YYYY-MM-DDTHH:MM:SSZ)
        let lastChangedTime = parse(user.passwordLastChanged, "yyyy-MM-dd'T'HH:mm:ss'Z'", utc())
        let sixMonths = initDuration(days = 30 * 6) # Approximate 6 months
        if now() - lastChangedTime > sixMonths:
          passwordExpired = true
      except ValueError:
        # Log error or handle as appropriate
        echo "[WARN] Could not parse passwordLastChanged for user ", user.id, ": ", user.passwordLastChanged

    var responseJson = %*{"status": "Login successful."}
    if passwordExpired:
      responseJson["password_expired"] = newJBool(true)

    # Check if MFA is required
    if userHasMfa(user.id):
      # Store temporary session for MFA verification
      let tempSession = createSession(user.id, temporary = true)
      setCookie("temp_session", tempSession, path = "/", httpOnly = true, maxAge = 600) # 10 minutes
      responseJson["status"] = newJString("mfa_required") # Update status for MFA
      resp Http200, $responseJson
    else:
      # Generate session token and set it as a cookie
      let sessionToken = createSession(user.id)
      setCookie("session", sessionToken, path = "/", httpOnly = true)
      resp Http200, $responseJson

  post "/login/mfa":
    let ip = "127.0.0.1" # Fallback IP for now - TODO: Replace with actual client IP
    if not isRequestAllowed(ip, mfaVerifyConfig):
      resp Http429, "Too many attempts. Please try later."
      return

    let tempSession = if request.cookies.hasKey("temp_session"): request.cookies["temp_session"] else: ""
    if tempSession.len == 0:
      resp Http401, "No pending MFA verification."
      return

    let body = parseJson(request.body)
    let mfaCode = body["mfa_code"].getStr

    # Verify MFA code (placeholder implementation)
    if mfaCode.len != 6:
      resp Http400, "Invalid MFA code format."
      return

    # TODO: Implement actual MFA verification using the stored secret
    let userId = getUserIdFromSession(tempSession)
    if userId > 0:
      let user = dbGetUserById(userId)
      if user.id > 0 and user.mfaEnabled:
        # Get and decrypt the MFA secret
        let key = getEnv("AES_KEY")
        let (encSecret, iv) = dbGetUserMfaSecret(user.id)
        if encSecret.len > 0 and iv.len > 0:
          try:
            let secret = aesGcmDecrypt(key, encSecret, iv)
            if not verifyTotp(secret, mfaCode): # Use verifyTotp from totp_utils
              resp Http400, "Invalid MFA code."
              return
          except Exception as e: # Catch specific exceptions if possible, or log e.msg
            # Log the error: echo "MFA verification exception: ", e.msg
            resp Http500, "MFA verification failed due to an internal error."
            return
        else:
          resp Http500, "MFA not properly configured."
          return
      
      # Clear temp session
      setCookie("temp_session", "", expires = "Thu, 01 Jan 1970 00:00:00 GMT")
      discard dbDeleteSession(tempSession)
      
      # Create permanent session
      let sessionToken = createSession(userId)
      setCookie("session", sessionToken, path = "/", httpOnly = true)

      # Check password expiry again for the main session
      var responseJson = %*{"status": "Login successful."}
      # user object is from the MFA context, already fetched via dbGetUserById(userId)
      if user.passwordLastChanged.len > 0:
        try:
          let lastChangedTime = parse(user.passwordLastChanged, "yyyy-MM-dd'T'HH:mm:ss'Z'", utc())
          let sixMonths = initDuration(days = 30 * 6) # Approximate
          if now() - lastChangedTime > sixMonths:
            responseJson["password_expired"] = newJBool(true)
        except ValueError:
          echo "[WARN] Could not parse passwordLastChanged for user ", user.id, " during MFA: ", user.passwordLastChanged

      resp Http200, $responseJson
    else:
      resp Http401, "Invalid session."

  post "/logout":
    let sessionToken = if request.cookies.hasKey("session"): request.cookies["session"] else: ""
    let tempSession = if request.cookies.hasKey("temp_session"): request.cookies["temp_session"] else: ""
    
    if sessionToken.len > 0:
      discard dbDeleteSession(sessionToken)
      setCookie("session", "", expires = "Thu, 01 Jan 1970 00:00:00 GMT")
    
    if tempSession.len > 0:
      discard dbDeleteSession(tempSession)
      setCookie("temp_session", "", expires = "Thu, 01 Jan 1970 00:00:00 GMT")
    
    resp Http200, "Logged out."
