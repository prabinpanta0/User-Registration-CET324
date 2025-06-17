import jester, json, times # Added times
import ../db/db
import ../routes/login
import ../crypto/password # Added crypto import
import ../utils/hibp # Added HIBP import
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
  get "/dashboard":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
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
    let body = parseJson(request.body)
    let current = body["current_password"].getStr
    let newpw = body["new_password"].getStr
    let confirm = body["confirm_new_password"].getStr
    if newpw != confirm:
      resp Http400, "Passwords do not match."
      return
    if not verifyPassword(current, user.passwordSalt, user.passwordHash):
      resp Http401, "Current password incorrect."
      return
    if not validPassword(newpw): # Assuming validPassword is now imported
      resp Http400, "Password does not meet requirements."
      return

    # Check if new password is pwned
    if await isPasswordPwned(newpw):
      resp Http400, "This new password has been exposed in data breaches. Please choose a different one."
      return

    let salt = generateSalt() # Corrected function name
    let hash = hashPassword(newpw, salt) # Assuming hashPassword is from ../crypto/password
    if not dbUpdateUserPassword(user.id, hash, salt):
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
    let body = parseJson(request.body)
    let sessionId = body["session_id"].getInt
    if not deleteSessionById(sessionId):
      resp Http500, "Failed to terminate session."
      return
    resp Http200, "Session terminated." 