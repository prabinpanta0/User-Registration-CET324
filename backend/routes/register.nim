import jester, strutils, json, sequtils, times
import ../crypto/password
import ../db/db
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

proc verifyCaptcha(ip, captcha: string): bool =
  # Simplified captcha verification for now
  result = true

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

    # Check if password is pwned
    if await isPasswordPwned(password):
      resp Http400, "This password has been exposed in data breaches. Please choose a different password."
      return

    let salt = generateSalt()
    let hash = hashPassword(password, salt)
    
    echo "[DEBUG] Attempting to insert user: ", username, " with email: ", email
    let insertResult = dbInsertUser(username, email, hash, salt)
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
