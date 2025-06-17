import jester, json, options, times
import ../db/db
import ../utils/jwt_utils
import ../utils/email_sender # For sending emails and getBaseUrl
import ../utils/csrf_validator # Import CSRF validator
import ../utils/audit_log # For new audit logging
import ../crypto/password   # For hashPassword, generateSalt
import ../utils/hibp        # For isPasswordPwned
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
      # Token validation failed (expired, bad signature, etc.)
      discard logAuditEvent("EMAIL_VERIFY_TOKEN_VALIDATION_FAILURE", request, additionalData = %*{"reason": "validateJwtToken returned none", "token": token})
      resp Http400, "Invalid or expired verification token."
      return

    let claims = claimsOption.get()
    if not claims.hasKey("user_id") or not claims.hasKey("type") or \
       claims["type"].getStr() != "email_verification":
      discard logAuditEvent("EMAIL_VERIFY_TOKEN_INVALID_PAYLOAD", request, additionalData = %*{"reason": "Missing user_id or type, or type mismatch", "claims": $claims})
      resp Http400, "Invalid token type or payload."
      return

    let userId = claims["user_id"].getInt()
    if userId == 0:
      discard logAuditEvent("EMAIL_VERIFY_TOKEN_INVALID_USERID", request, additionalData = %*{"reason": "User ID in token is 0 or invalid", "claims": $claims})
      resp Http400, "Invalid user ID in token."
      return

    ensureDbConnection()
    let user = dbGetUserById(userId)
    if user.id == 0:
      discard logAuditEvent("EMAIL_VERIFY_USER_NOT_FOUND", request, userId = some(userId), additionalData = %*{"reason": "User ID from token not found in DB"})
      resp Http400, "User not found for this token."
      return

    if user.isVerified:
      discard logAuditEvent("EMAIL_VERIFY_ALREADY_VERIFIED", request, userId = some(userId))
      resp Http200, "Email already verified. You can log in."
      return

    if dbSetUserVerified(userId):
      discard logAuditEvent("EMAIL_VERIFY_SUCCESS", request, userId = some(userId))
      resp Http200, "Email verified successfully. You can now log in."
    else:
      discard logAuditEvent("EMAIL_VERIFY_DB_UPDATE_FAILURE", request, userId = some(userId), additionalData = %*{"reason": "dbSetUserVerified returned false"})
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
      let currentUserId = if isPostSessionContext: dbGetSessionByToken(sessionTokenCookie).userId.some else: none[int]()
      discard logAuditEvent("CSRF_VALIDATION_FAILED", request, userId = currentUserId, additionalData=%*{"route": "/request-password-reset", "context": if isPostSessionContext: "session" else: "pre-session"})
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

    if email.len == 0 or not email.contains("@"):
      discard logAuditEvent("PASSWORD_RESET_REQUEST_INVALID_EMAIL_FORMAT", request, additionalData = %*{"provided_email": email})
      resp Http400, "Invalid email format."
      return

    ensureDbConnection()
    let user = dbGetUserByUsernameOrEmail(email)

    if user.id != 0 and user.isVerified:
      let resetClaims = %*{"user_id": user.id, "type": "password_reset"}
      let resetToken = generateJwtToken(resetClaims, 1 * 3600) # 1 hour expiry

      if resetToken.len > 0:
        let baseUrl = getBaseUrl()
        let resetLink = baseUrl & "/reset-password?token=" & resetToken
        let emailSubject = "Password Reset Request"
        let emailBody = "Please click the link below to reset your password:\n\n" &
                        resetLink & "\n\nThis link will expire in 1 hour. " &
                        "If you did not request a password reset, please ignore this email."

        let emailSent = await sendEmail(user.email, emailSubject, emailBody)
        if not emailSent:
          discard logAuditEvent("PASSWORD_RESET_EMAIL_SEND_FAILURE", request, some(user.id), additionalData = %*{"email": user.email})
        else:
          discard logAuditEvent("PASSWORD_RESET_EMAIL_SENT_SUCCESS", request, some(user.id), additionalData = %*{"email": user.email})
      else:
        discard logAuditEvent("PASSWORD_RESET_TOKEN_GEN_FAILURE", request, some(user.id))
    else:
      # User not found or not verified, log this attempt if desired (might contribute to enumeration if logs are monitored for specific emails)
      # For now, just falling through to generic response.
      discard logAuditEvent("PASSWORD_RESET_REQUEST_USER_NOT_FOUND_OR_UNVERIFIED", request, additionalData = %*{"attempted_email": email})

    resp Http200, "If an account with that email exists and is verified, a password reset link has been sent."

  post "/perform-password-reset":
    # This form is accessed via an email link, typically meaning no active session for the user.
    # So, CSRF protection relies on the double submit cookie (`csrf_token_value`)
    # that should have been set when the page with this form was loaded (after calling /csrf-token).
    if not verifyCsrf(request, isPreSession = true):
      # Log CSRF failure. User ID not available yet from token.
      discard logAuditEvent("CSRF_VALIDATION_FAILED", request, additionalData=%*{"route": "/perform-password-reset", "context": "pre-session"})
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
      discard logAuditEvent("PASSWORD_RESET_PERFORM_FAILURE_NO_TOKEN", request)
      resp Http400, "Password reset token is missing."
      return
    if newPassword != confirmPassword:
      discard logAuditEvent("PASSWORD_RESET_PERFORM_FAILURE_PW_MISMATCH", request)
      resp Http400, "New passwords do not match."
      return

    if not validPassword(newPassword):
      discard logAuditEvent("PASSWORD_RESET_PERFORM_FAILURE_INVALID_PW", request)
      resp Http400, "Password does not meet complexity requirements."
      return

    let claimsOption = validateJwtToken(token)
    var tempUserId: Option[int] = none() # For logging before full claim validation
    if claimsOption.isSome() and claimsOption.get().hasKey("user_id"):
        tempUserId = some(claimsOption.get()["user_id"].getInt())

    if claimsOption.isNone():
      discard logAuditEvent("PASSWORD_RESET_PERFORM_TOKEN_VALIDATION_FAILURE", request, userId=tempUserId, additionalData = %*{"reason": "validateJwtToken returned none"})
      resp Http400, "Invalid or expired password reset token."
      return

    let claims = claimsOption.get()
    if not claims.hasKey("user_id") or not claims.hasKey("type") or \
       claims["type"].getStr() != "password_reset":
      discard logAuditEvent("PASSWORD_RESET_PERFORM_TOKEN_INVALID_PAYLOAD", request, userId=tempUserId, additionalData = %*{"reason": "Missing user_id or type, or type mismatch", "claims": $claims})
      resp Http400, "Invalid token type or payload for password reset."
      return

    let userId = claims["user_id"].getInt()
    if userId == 0:
      discard logAuditEvent("PASSWORD_RESET_PERFORM_TOKEN_INVALID_USERID", request, additionalData = %*{"reason": "User ID in token is 0", "claims": $claims})
      resp Http400, "Invalid user ID in reset token."
      return

    if await isPasswordPwned(newPassword):
      discard logAuditEvent("PASSWORD_RESET_PERFORM_FAILURE_PWNED_PW", request, some(userId))
      resp Http400, "This new password has been exposed in data breaches. Please choose a different one."
      return

    ensureDbConnection()
    let user = dbGetUserById(userId)
    if user.id == 0:
      discard logAuditEvent("PASSWORD_RESET_PERFORM_USER_NOT_FOUND", request, some(userId), additionalData = %*{"reason": "User ID from token not found in DB"})
      resp Http400, "User not found for this reset token."
      return

    let salt = generateSalt()
    let hash = hashPassword(newPassword, salt)

    if dbUpdateUserPassword(userId, hash, salt):
      discard logAuditEvent("PASSWORD_RESET_PERFORM_SUCCESS", request, some(userId))
      resp Http200, "Password reset successfully. You can now log in with your new password."
    else:
      discard logAuditEvent("PASSWORD_RESET_PERFORM_DB_UPDATE_FAILURE", request, some(userId), additionalData=%*{"reason": "dbUpdateUserPassword failed, possibly history or other DB error"})
      resp Http400, "Failed to reset password. The new password may have been used previously, or a server error occurred."

  # discard routes # No longer needed if all routes are used.
