import jester, json, times, sequtils, random # Added random for randomize()
import ../db/db
import ../routes/login
import ../utils/mfa_recovery_utils # For generateRecoveryCodes
import ../crypto/password # Added crypto import
import ../utils/hibp # Added HIBP import
import ../utils/csrf_validator # Import CSRF validator
import ../routes/register import validPassword # Import specific proc

# Helper to check password expiry
proc isPasswordExpired(passwordLastChanged: string): bool =
  if passwordLastChanged.len == 0:
    return false # Should not happen for users with history, but handle defensively
  try:
    # Assuming passwordLastChanged is in ISO 8601 format from DB (YYYY-MM-DDTHH:MM:SSZ)
    let lastChangedTime = parse(passwordLastChanged, "yyyy-MM-dd'T'HH:mm:ss'Z'", utc())
    let sixMonths = initDuration(days = 30 * 6) # Approximate 6 months
    return now() - lastChangedTime > sixMonths
  except ValueError:
    # Log error: echo "Could not parse passwordLastChanged timestamp: ", passwordLastChanged
    return false # Default to not expired if parsing fails

routes:
  get "/session-check":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, %*{"authenticated": false}
      return
    
    resp Http200, %*{
      "authenticated": true,
      "user_id": user.id,
      "username": user.username,
      "mfa_enabled": user.mfaEnabled
    }

  get "/dashboard":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    # Enforce MFA setup for new users
    if not user.mfaEnabled:
      resp Http403, %*{
        "error": "MFA setup required",
        "redirect": "/mfa/setup",
        "message": "You must set up MFA before accessing the dashboard."
      }
      return

    let expired = isPasswordExpired(user.passwordLastChanged)
    resp Http200, %*{
      "username": user.username,
      "email": user.email,
      "last_login": user.lastLogin,
      "mfa_enabled": user.mfaEnabled,
      "password_expired": expired
    }

  post "/change-password":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    # CSRF Check (session-bound)
    if not verifyCsrf(request):
      resp Http403, "CSRF token validation failed."
      return

    let body = parseJson(request.body)
    let current = body["current_password"].getStr
    let newpw = body["new_password"].getStr
    let confirm = body["confirm_new_password"].getStr
    if newpw != confirm:
      resp Http400, "Passwords do not match."
      return
    # Verify current password using the same logic as login
    var currentPasswordVerified = false
    if verifyPassword(current, user.passwordHash):
      currentPasswordVerified = true
    elif user.passwordSalt.len > 0:
      # Try legacy verification if salt exists
      if verifyPassword_sha256_legacy(current, user.passwordSalt, user.passwordHash):
        currentPasswordVerified = true
    
    if not currentPasswordVerified:
      resp Http401, "Current password incorrect."
      return
    if not validPassword(newpw): # Assuming validPassword is now imported
      resp Http400, "Password does not meet requirements."
      return

    # Check if new password is pwned
    if await isPasswordPwned(newpw):
      resp Http400, "This new password has been exposed in data breaches. Please choose a different one."
      return

    let hash = hashPassword(newpw) # Use Argon2id hashing without separate salt
    if not dbUpdateUserPassword(user.id, hash, ""):
      # dbUpdateUserPassword returns false if the new password is in the recent history,
      # or if there was a general database error during the update.
      resp Http400, "Failed to update password. The new password may be one of the last 5 passwords used, or a server error occurred. Please try a different password."
      return
    resp Http200, "Password changed."

  post "/sessions/list":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return
    let sessions = listSessionsForUser(user.id)
    resp Http200, %*sessions

  post "/sessions/terminate":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    # CSRF Check (session-bound)
    if not verifyCsrf(request):
      resp Http403, "CSRF token validation failed."
      return

    let body = parseJson(request.body)
    let sessionId = body["session_id"].getInt
    if not deleteSessionById(sessionId):
      resp Http500, "Failed to terminate session."
      return
    resp Http200, "Session terminated."

  # Frontend expects GET /dashboard/info
  get "/dashboard/info":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return
    # Enforce MFA setup for new users
    if not user.mfaEnabled:
      resp Http403, %*{
        "error": "MFA setup required",
        "redirect": "/mfa/setup",
        "message": "You must set up MFA before accessing the dashboard."
      }
      return
    let expired = isPasswordExpired(user.passwordLastChanged)
    resp Http200, %*{
      "username": user.username,
      "email": user.email,
      "last_login": user.lastLogin,
      "mfa_enabled": user.mfaEnabled,
      "password_expired": expired
    }

  # Frontend expects GET /dashboard/sessions
  get "/dashboard/sessions":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return
    let sessions = listSessionsForUser(user.id)
    resp Http200, %*sessions

  get "/mfa/recovery-codes/status":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    # CSRF check might not be strictly necessary for GETting status,
    # but if there's any sensitivity, it can be added.
    # For now, omitting for a status check.

    if not user.mfaEnabled:
      # If MFA is not enabled, they shouldn't have recovery codes.
      resp Http200, %*{"has_codes": false, "count": 0, "mfa_enabled": false}
      return

    let hashedCodes = dbGetUserRecoveryCodes(user.id)
    let count = hashedCodes.len

    resp Http200, %*{
      "has_codes": count > 0,
      "count": count,
      "mfa_enabled": true
    }

  post "/mfa/recovery-codes/regenerate":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    if not verifyCsrf(request):
      resp Http403, "CSRF token validation failed."
      return

    if not user.mfaEnabled:
      # Should not happen if UI is correct, but good to check.
      resp Http400, "MFA is not enabled for this account."
      return

    randomize() # Ensure RNG is seeded
    let (plaintextCodes, hashedCodes) = generateRecoveryCodes()

    if not dbSetUserRecoveryCodes(user.id, hashedCodes):
      echo "[ERROR][RECOVERY_REGEN] Failed to store new recovery codes for user ID: ", user.id
      resp Http500, "Failed to regenerate recovery codes. Please try again."
      return

    echo "[AUDIT][RECOVERY_REGEN] Successfully regenerated recovery codes for user ID: ", user.id

    var responseJson = %*{
      "status": "success",
      "message": "Recovery codes regenerated successfully.",
      "recovery_codes": newJArray()
    }
    for code in plaintextCodes:
      responseJson["recovery_codes"].add(newJString(code))

    resp Http200, $responseJson