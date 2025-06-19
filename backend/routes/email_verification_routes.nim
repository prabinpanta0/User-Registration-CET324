import jester, json, options, times, random, strutils
import ../db/db
import ../utils/jwt_utils
import ../utils/email_sender # For sending emails and getBaseUrl
import ../utils/csrf_validator # Import CSRF validator
import ../crypto/password   # For hashPassword, generateSalt
import ../utils/hibp        # For isPasswordPwned
import ../routes/login import createSession # Import createSession function
# Assuming validPassword from register.nim is needed, or similar logic here.
# For now, let's use a direct import if register.nim is small or create a shared util.
# To avoid circular deps if register imports this file, better to have password validation as a shared util.
# For this step, let's assume a basic length check. A proper solution would use the shared `validPassword`.
import ../routes/register import validPassword # Assuming this is okay for now.

routes:
  get "/verify-email":
    let token = request.params.get("token", "")
    if token.len == 0:
      resp Http400, "Verification token is missing."
      return

    let claimsOption = validateJwtToken(token)
    if claimsOption.isNone():
      resp Http400, "Invalid or expired verification token."
      return

    let claims = claimsOption.get()
    if not claims.hasKey("user_id") or not claims.hasKey("type") or \
       claims["type"].getStr() != "email_verification":
      resp Http400, "Invalid token type or payload."
      return

    let userId = claims["user_id"].getInt() # getInt will default to 0 if not a number or missing
    if userId == 0: # Check if getInt failed or if user_id was actually 0 (though unlikely for DB IDs)
        try: # More robust check for user_id
            let userIdFromStr = claims["user_id"].getStr()
            if userIdFromStr.len > 0 and parseInt(userIdFromStr) > 0:
                # This case is complex, assume getInt() is sufficient for JsonNode from nim-jwt
                # If nim-jwt stores numbers as strings in claims, then manual parsing is needed.
                # For now, assuming getInt() works as expected for numeric claims.
                discard
            else:
                resp Http400, "Invalid user ID in token."
                return
        except ValueError: # if getStr then parseInt fails
            resp Http400, "Invalid user ID format in token."
            return
        except KeyError: # if "user_id" key is missing (already checked by hasKey)
            resp Http400, "User ID missing in token."
            return


    # Ensure database connection
    ensureDbConnection()

    let user = dbGetUserById(userId) # Fetch user to ensure they exist
    if user.id == 0:
        resp Http400, "User not found for this token."
        return

    if user.isVerified:
        resp Http200, %*{"status": "already_verified", "redirect": "/login", "message": "Email already verified. You can log in."}
        return

    if dbSetUserVerified(userId):
      # Create a session for the newly verified user
      let sessionToken = createSession(userId)
      # Set cookie with explicit settings for proxy compatibility
      var sessionCookie = newCookie("session", sessionToken)
      sessionCookie.path = "/"
      sessionCookie.httpOnly = true
      sessionCookie.sameSite = SameSite.Lax  # More permissive for cross-domain
      # Don't set domain to allow it to work across proxy
      setCookie(sessionCookie)
      
      echo "[DEBUG] Session cookie set for user ", userId, " token: ", sessionToken[0..10], "..."
      
      # Redirect to MFA setup since new users need to set up MFA
      resp Http200, %*{"status": "verified", "redirect": "/mfa/setup", "message": "Email verified successfully. Setting up MFA..."}
    else:
      # Log this server-side, as it's an internal issue if token was valid but DB update failed.
      echo "[ERROR] Failed to set user as verified in DB for user ID: ", userId
      resp Http500, "Failed to verify email. Please try again later or contact support."


  post "/request-password-reset":
    # Determine if it's a pre-session or post-session context for CSRF
    let sessionTokenCookie = request.cookies.getOrDefault("session", "")
    var isPostSessionContext = false
    if sessionTokenCookie.len > 0:
      let userSession = dbGetSessionByToken(sessionTokenCookie) # Might need ensureDbConnection if not done by dbGetSessionByToken
      if userSession.id != 0:
        isPostSessionContext = true

    if not verifyCsrf(request, isPreSession = not isPostSessionContext):
      resp Http403, "CSRF token validation failed."
      return

    # Clear pre-session CSRF cookie if it was used
    if not isPostSessionContext:
      var csrfCookieToClear = newCookie("csrf_token_value", "", expires = past())
      csrfCookieToClear.path = "/"
      # csrfCookieToClear.secure = true # if set with Secure
      csrfCookieToClear.sameSite = SameSite.Strict
      setCookie(csrfCookieToClear)

    let body = parseJson(request.body)
    let email = body.getOrDefault("email", "").getStr()

    if email.len == 0 or not email.contains("@"): # Basic email validation
      resp Http400, "Invalid email format."
      return

    ensureDbConnection()
    let user = dbGetUserByUsernameOrEmail(email)

    if user.id != 0 and user.isVerified: # User exists and is verified
      let resetClaims = %*{"user_id": user.id, "type": "password_reset"}
      # Expiry: 1 hour for password reset
      let resetToken = generateJwtToken(resetClaims, 1 * 3600)

      if resetToken.len > 0:
        let baseUrl = getBaseUrl()
        let resetLink = baseUrl & "/reset-password?token=" & resetToken # Assuming frontend route
        let emailSubject = "Password Reset Request"
        let emailBody = "Please click the link below to reset your password:\n\n" &
                        resetLink & "\n\nThis link will expire in 1 hour. " &
                        "If you did not request a password reset, please ignore this email."

        let emailSent = await sendEmail(user.email, emailSubject, emailBody)
        if not emailSent:
          echo "[ERROR] Failed to send password reset email to ", user.email, " for user ID ", user.id
          # Still respond with generic message below
        else:
          echo "[INFO] Password reset email sent to ", user.email, " for user ID ", user.id
      else:
        echo "[ERROR] Failed to generate password reset token for user ID ", user.id
        # Still respond with generic message

    # Always respond with a generic success message to prevent email enumeration
    resp Http200, "If an account with that email exists and is verified, a password reset link has been sent."

  post "/perform-password-reset":
    # This form is accessed via an email link, typically meaning no active session for the user.
    # So, CSRF protection relies on the double submit cookie (`csrf_token_value`)
    # that should have been set when the page with this form was loaded (after calling /csrf-token).
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
    let token = body.getOrDefault("token", "").getStr()
    let newPassword = body.getOrDefault("new_password", "").getStr()
    let confirmPassword = body.getOrDefault("confirm_password", "").getStr()

    if token.len == 0:
      resp Http400, "Password reset token is missing."
      return
    if newPassword != confirmPassword:
      resp Http400, "New passwords do not match."
      return

    # Use the shared validPassword logic
    if not validPassword(newPassword):
        resp Http400, "Password does not meet complexity requirements."
        return

    let claimsOption = validateJwtToken(token)
    if claimsOption.isNone():
      resp Http400, "Invalid or expired password reset token."
      return

    let claims = claimsOption.get()
    if not claims.hasKey("user_id") or not claims.hasKey("type") or \
       claims["type"].getStr() != "password_reset":
      resp Http400, "Invalid token type or payload for password reset."
      return

    let userId = claims["user_id"].getInt()
    if userId == 0: # Basic check
        resp Http400, "Invalid user ID in reset token."
        return

    # HIBP Check for the new password
    if await isPasswordPwned(newPassword):
      resp Http400, "This new password has been exposed in data breaches. Please choose a different one."
      return

    ensureDbConnection()
    let user = dbGetUserById(userId) # Ensure user still exists
    if user.id == 0:
        resp Http400, "User not found for this reset token."
        return

    # Hash the new password
    let salt = generateSalt()
    let hash = hashPassword(newPassword, salt)

    # dbUpdateUserPassword also checks password history
    if dbUpdateUserPassword(userId, hash, salt):
      resp Http200, "Password reset successfully. You can now log in with your new password."
    else:
      # This could be due to history check in dbUpdateUserPassword or other DB error
      resp Http400, "Failed to reset password. The new password may have been used previously, or a server error occurred."

  post "/verify-email-code":
    # This is for code-based verification, using CSRF protection for pre-session
    if not verifyCsrf(request, isPreSession = true):
      resp Http403, "CSRF token validation failed."
      return

    # Clear the CSRF cookie after successful use
    var csrfCookieToClear = newCookie("csrf_token_value", "", expires = past())
    csrfCookieToClear.path = "/"
    csrfCookieToClear.sameSite = SameSite.Strict
    setCookie(csrfCookieToClear)

    let code = request.params.get("code", "")
    if code.len != 6:
      resp Http400, "Invalid verification code format. Code must be 6 digits."
      return

    # Validate that code contains only digits
    for c in code:
      if not c.isDigit:
        resp Http400, "Invalid verification code format. Code must contain only digits."
        return

    ensureDbConnection()

    # Find user by verification code (we need to modify this approach)
    # Since we don't have user_id in the request, we need to find the user by the code
    # Let's create a function to get user by verification code
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
      resp Http400, %*{"status": "already_verified", "redirect": "/login", "message": "Email is already verified."}
      return

    # Verify the code and mark as used
    if dbVerifyEmailCode(userId, code):
      # Set user as verified
      if dbSetUserVerified(userId):
        # Create a session for the newly verified user
        let sessionToken = createSession(userId)
        # Set cookie with explicit settings for compatibility
        var sessionCookie = newCookie("session", sessionToken)
        sessionCookie.path = "/"
        sessionCookie.httpOnly = true
        sessionCookie.sameSite = SameSite.Lax  # More permissive for cross-domain
        setCookie(sessionCookie)
        
        echo "[DEBUG] Session cookie set for user ", userId, " token: ", sessionToken[0..10], "..."
        
        # Redirect to MFA setup since new users need to set up MFA
        resp Http200, %*{"status": "verified", "redirect": "/mfa/setup", "message": "Email verified successfully. Setting up MFA..."}
      else:
        echo "[ERROR] Failed to set user as verified after code validation for user ID: ", userId
        resp Http500, "Failed to complete verification. Please try again."
    else:
      resp Http400, "Invalid or expired verification code."

  # discard routes # No longer needed if all routes are used.
