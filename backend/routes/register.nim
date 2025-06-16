import jester, strutils, json, sequtils
import ../crypto/password
import ../db/db
import ../utils/rate_limit
import ../routes/login

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
    let ip = "127.0.0.1"  # Fallback IP for now
    if not checkRateLimit(ip, "register"):
      resp Http429, "Too many attempts. Please try later."
      return

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
    
    # Create a session for the newly registered user
    let sessionToken = createSession(user.id)
    setCookie("session", sessionToken, path = "/", httpOnly = true)
    
    resp Http200, "Registration successful. Redirecting to MFA setup."
