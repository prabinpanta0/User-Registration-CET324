import jester, json
import ../db/db
import ../routes/login

routes:
  get "/dashboard":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return
    resp Http200, %*{
      "username": user.username,
      "email": user.email,
      "last_login": user.lastLogin,
      "mfa_enabled": user.mfaEnabled
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
    if not validPassword(newpw):
      resp Http400, "Password does not meet requirements."
      return
    let salt = genSalt()
    let hash = hashPassword(newpw, salt)
    if not dbUpdateUserPassword(user.id, hash, salt):
      resp Http500, "Failed to update password."
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