import jester, strutils, json, sequtils, times, asyncdispatch, httpclient, options, random
import ../crypto/password
import ../db/db
import ../utils/env # For getHCaptchaSecretKey
import ../config # For HCaptchaSiteverifyURL
import ../utils/rate_limit
import ../utils/hibp # Added HIBP import
import ../utils/email_sender # Added Email Sender
import ../utils/jwt_utils # Added JWT Utils
import ../utils/csrf_validator # Import CSRF validator
import ../routes/login

# Rate Limiting Configuration for Registration
const registerAttemptConfig = RateLimitConfig(
  routeIdentifier: "register_attempt",
  maxAttemptsShortTerm: 10,       # Max 10 registration attempts
  windowSecShortTerm: 3600,     # within a 1-hour window
  blockDurationSecLongTerm: 86400 # Long-term DB block for 24 hours if limit exceeded
)

proc validPassword(password: string): bool =
  result = password.len >= 10 and 
           password.toSeq.anyIt(it.isUpperAscii) and 
           password.toSeq.anyIt(it.isDigit) and 
           password.toSeq.anyIt(not (it.isAlphaAscii or it.isDigit))

proc validUsername(username: string): bool =
  result = username.len in 3..20 and username.toSeq.allIt(it.isAlphaAscii or it.isDigit or it == '_')

proc validEmail(email: string): bool =
  result = email.contains("@") and email.contains(".") and email.len > 5

proc verifyCaptcha*(clientResponseToken: string, clientIpAddress: string = ""): Future[bool] {.async.} =
  let secretKey = getHCaptchaSecretKey()
  if secretKey.len == 0:
    echo "[ERROR] hCaptcha secret key is not configured. Captcha verification skipped and failed."
    return false

  var content = newMultipartData()
  content.add("secret", secretKey)
  content.add("response", clientResponseToken)

  # Add remoteip if provided and not empty.
  # Ensure clientIpAddress is the actual user IP, considering X-Forwarded-For if behind a proxy.
  if clientIpAddress.len > 0:
    content.add("remoteip", clientIpAddress)

    echo "[DEBUG] Verifying hCaptcha token for IP: ", clientIpAddress

  try:
    let client = newAsyncHttpClient()
    # Set timeout to 3 seconds for faster response
    client.timeout = 3000
    # The httpclient.post consumes the MultipartData, so no need to manage its lifecycle explicitly here.
    let response = await client.post(HCaptchaSiteverifyURL, multipart = content)

    if response.code != Http200:
      echo "[ERROR] hCaptcha request failed with status: ", response.code, " Body: ", await response.body
      client.close()
      return false

    let responseBody = await response.body
    echo "[DEBUG] hCaptcha verification result: ", if jsonResponse.hasKey("success") and jsonResponse["success"].getBool(false): "SUCCESS" else: "FAILED"
    let jsonResponse = parseJson(responseBody)

    client.close()
    if jsonResponse.hasKey("success") and jsonResponse["success"].getBool(false):
      echo "[INFO] hCaptcha verification successful."
      return true
    else:
      let errorCodes = if jsonResponse.hasKey("error-codes"): jsonResponse["error-codes"].getStr() else: "N/A"
      echo "[INFO] hCaptcha verification failed. Error codes: ", errorCodes
      return false

  except Exception as e:
    echo "[ERROR] Exception during hCaptcha verification: ", e.msg
    return false

proc genVerificationCode*(): string =
  # Generate a 6-digit numeric verification code
  randomize()
  result = ""
  for i in 0..<6:
    result.add($rand(0..9))

routes:
  post "/register":
    let startTime = epochTime()
    let ip = "127.0.0.1"  # Fallback IP for now - TODO: Replace with actual client IP
    if not isRequestAllowed(ip, registerAttemptConfig):
      resp Http429, "Too many registration attempts. Please try later."
      return

    echo "[DEBUG] Registration started at: ", startTime
    
    # CSRF Check (pre-session)
    if not verifyCsrf(request, isPreSession = true):
      resp Http403, "CSRF token validation failed."
      return
    echo "[DEBUG] CSRF validation completed in: ", epochTime() - startTime, "s"
    # Clear the double submit cookie after successful use
    var csrfCookieToClear = newCookie("csrf_token_value", "", expires = past())
    csrfCookieToClear.path = "/"
    # csrfCookieToClear.secure = true # if set with Secure
    csrfCookieToClear.sameSite = SameSite.Strict
    setCookie(csrfCookieToClear)

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

    # Perform CAPTCHA verification
    # For clientIp, it's better to extract it reliably, e.g. from X-Forwarded-For if behind proxy.
    # For now, passing the ip variable which is "127.0.0.1" as a placeholder or empty.
    # let clientIpForCaptcha = request.headers.getOrDefault("X-Forwarded-For", ip) # Example
    echo "[DEBUG] Starting CAPTCHA verification..."
    let captchaStartTime = epochTime()
    if not await verifyCaptcha(captchaToken, ip): # Using the placeholder 'ip' for now
      resp Http400, "Invalid CAPTCHA. Please try again."
      return
    echo "[DEBUG] CAPTCHA verification completed in: ", epochTime() - captchaStartTime, "s"

    # Check if password is pwned (only for weaker passwords to improve performance)
    # Skip HIBP check for very strong passwords to improve performance
    let isWeakPassword = password.len < 12 or not (
      password.toSeq.anyIt(it.isUpperAscii) and 
      password.toSeq.anyIt(it.isLowerAscii) and
      password.toSeq.anyIt(it.isDigit) and 
      password.toSeq.anyIt(not (it.isAlphaAscii or it.isDigit))
    )
    
    if isWeakPassword:
      echo "[DEBUG] Checking weak password against HIBP..."
      if await isPasswordPwned(password):
        resp Http400, "This password has been exposed in data breaches. Please choose a different password."
        return
    else:
      echo "[DEBUG] Strong password detected, skipping HIBP check for performance"

    # Argon2id handles salt internally; hashPassword now only takes the password.
    # The returned hash includes the salt.
    echo "[DEBUG] Starting password hashing..."
    let hashStartTime = epochTime()
    let hash = hashPassword(password)
    echo "[DEBUG] Password hashing completed in: ", epochTime() - hashStartTime, "s"
    
    # Check if username or email already exists before attempting insert
    if dbUserExists(username):
      resp Http400, "Username already exists. Please choose a different username."
      return
    
    if dbUserExistsByEmail(email):
      resp Http400, "Email already registered. Please use a different email or try logging in."
      return
    
    echo "[DEBUG] Attempting to insert user: ", username
    # Pass an empty string for salt, as it's now part of the hash.
    # The db schema & dbInsertUser signature will be updated in a later step.
    let insertResult = dbInsertUser(username, email, hash, "")
    echo "[DEBUG] Insert result: ", insertResult
    
    if not insertResult:
      echo "[ERROR] Failed to insert user into database"
      resp Http500, "User registration failed. Please try again."
      return
    
    # Get the newly created user
    let user = dbGetUserByUsernameOrEmail(username)
    if user.id == 0:
      resp Http500, "User creation failed."
      return
    
    # User inserted successfully (is_verified is false by default)
    # Send verification email with both JWT token link and verification code
    let verificationClaims = %*{"user_id": user.id, "type": "email_verification"}
    # Expiry: 24 hours for email verification
    let verificationToken = generateJwtToken(verificationClaims, 24 * 3600)

    # Generate a 6-digit verification code
    let verificationCode = genVerificationCode()
    echo "[INFO] Verification code for ", user.email, ": ", verificationCode
    let codeStored = dbCreateVerificationCode(user.id, verificationCode, 24)
    echo "[DEBUG] Code stored in DB: ", codeStored

    echo "[DEBUG] Starting email sending process..."
    let emailStartTime = epochTime()
    
    if verificationToken.len > 0 and codeStored:
      let baseUrl = getBaseUrl() # From email_sender or a common config
      let verificationLink = baseUrl & "/verify-email?token=" & verificationToken
      let emailSubject = "Verify your email address"
      let emailBody = "Please verify your email address using one of the following methods:\n\n" &
                      "Method 1: Click the link below:\n" & verificationLink & "\n\n" &
                      "Method 2: Enter this 6-digit code: " & verificationCode & "\n" &
                      "Visit: " & baseUrl & "/verify-email\n\n" &
                      "Both the link and code will expire in 24 hours."

      echo "[DEBUG] About to send email to: ", user.email
      # Send email asynchronously without blocking the response
      asyncCheck sendEmail(user.email, emailSubject, emailBody)
      echo "[DEBUG] Email send request initiated (async) in: ", epochTime() - emailStartTime, "s"
    else:
      echo "[ERROR] Failed to generate verification token or code for user ID ", user.id
      # Critical error, as user cannot verify. Consider if registration should fail here.

    # Do NOT create a session or log the user in.
    # The MFA setup redirect should also be conditional on verification, or handled post-verification.
    # For now, just inform user to check email.
    let totalTime = epochTime() - startTime
    echo "[DEBUG] Total registration process completed in: ", totalTime, "s"
    resp Http200, "Registration successful. Please check your email to verify your account."
