import jester, strutils, json, sequtils, times, asyncdispatch, httpclient, options
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

  echo "[DEBUG] Verifying hCaptcha token: ", clientResponseToken, " for IP: ", clientIpAddress

  try:
    let client = newAsyncHttpClient()
    # The httpclient.post consumes the MultipartData, so no need to manage its lifecycle explicitly here.
    let response = await client.post(HCaptchaSiteverifyURL, multipart = content)

    if response.code != Http200:
      echo "[ERROR] hCaptcha request failed with status: ", response.code, " Body: ", await response.body
      return false

    let responseBody = await response.body
    echo "[DEBUG] hCaptcha response body: ", responseBody
    let jsonResponse = parseJson(responseBody)

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
  finally:
    # newAsyncHttpClient doesn't strictly need close() for simple POSTs like this,
    # but if it were used for multiple requests or more complex scenarios, proper closing would be important.
    # For this single request, it's generally fine.
    discard

routes:
  post "/register":
    let ip = "127.0.0.1"  # Fallback IP for now - TODO: Replace with actual client IP
    if not isRequestAllowed(ip, registerAttemptConfig):
      resp Http429, "Too many registration attempts. Please try later."
      return

    # CSRF Check (pre-session)
    if not verifyCsrf(request, isPreSession = true):
      resp Http403, "CSRF token validation failed."
      return
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
    if not await verifyCaptcha(captchaToken, ip): # Using the placeholder 'ip' for now
      resp Http400, "Invalid CAPTCHA. Please try again."
      return

    # Check if password is pwned
    if await isPasswordPwned(password):
      resp Http400, "This password has been exposed in data breaches. Please choose a different password."
      return

    # Argon2id handles salt internally; hashPassword now only takes the password.
    # The returned hash includes the salt.
    let hash = hashPassword(password)
    
    echo "[DEBUG] Attempting to insert user: ", username, " with email: ", email
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
    # Send verification email
    let verificationClaims = %*{"user_id": user.id, "type": "email_verification"}
    # Expiry: 24 hours for email verification
    let verificationToken = generateJwtToken(verificationClaims, 24 * 3600)

    if verificationToken.len > 0:
      let baseUrl = getBaseUrl() # From email_sender or a common config
      let verificationLink = baseUrl & "/verify-email?token=" & verificationToken
      let emailSubject = "Verify your email address"
      let emailBody = "Please click the link below to verify your email address:\n\n" &
                      verificationLink & "\n\nThis link will expire in 24 hours."

      # Asynchronously send email, but don't block response to user
      # The `await` here will pause this specific request handling until email is sent or fails.
      # If sendEmail was truly async (e.g. using a thread pool), this would be non-blocking for the main loop.
      let emailSent = await sendEmail(user.email, emailSubject, emailBody)
      if not emailSent:
        echo "[ERROR] Failed to send verification email to ", user.email, " for user ID ", user.id
        # User is created but not verified. They might need a "resend verification" option later.
      else:
        echo "[INFO] Verification email sent to ", user.email, " for user ID ", user.id
    else:
      echo "[ERROR] Failed to generate verification token for user ID ", user.id
      # Critical error, as user cannot verify. Consider if registration should fail here.

    # Do NOT create a session or log the user in.
    # The MFA setup redirect should also be conditional on verification, or handled post-verification.
    # For now, just inform user to check email.
    resp Http200, "Registration successful. Please check your email to verify your account."
