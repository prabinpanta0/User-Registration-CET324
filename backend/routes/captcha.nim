import random, strutils, sequtils, jester, base64, times, nimcrypto/sha2
import ../db/db
import ../utils/audit_log

# Store captcha solutions temporarily in database
proc storeCaptchaSession(ip: string, solution: string): string =
  # Create a session ID for this captcha
  let sessionId = $sha256.digest(ip & $getTime() & solution)
  # Store in database with expiration (5 minutes)
  let expiresAt = getTime() + initDuration(minutes = 5)
  try:
    discard dbExecute("INSERT INTO captcha_sessions (session_id, ip_address, solution, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT (session_id) DO UPDATE SET solution = $3, expires_at = $4", 
                      sessionId, ip, solution, expiresAt.toUnix())
  except:
    echo "[ERROR] Failed to store captcha session: ", getCurrentExceptionMsg()
  return sessionId

proc verifyCaptchaSession*(sessionId: string, ip: string, userSolution: string): bool =
  try:
    let rows = dbAll("SELECT solution, expires_at FROM captcha_sessions WHERE session_id = $1 AND ip_address = $2", sessionId, ip)
    if rows.len == 0:
      echo "[DEBUG] No captcha session found for: ", sessionId
      return false
    
    let storedSolution = rows[0][0]
    let expiresAt = parseInt(rows[0][1])
    
    if getTime().toUnix() > expiresAt:
      echo "[DEBUG] Captcha session expired for: ", sessionId
      # Clean up expired session
      discard dbExecute("DELETE FROM captcha_sessions WHERE session_id = $1", sessionId)
      return false
    
    let verified = storedSolution.toLowerAscii() == userSolution.toLowerAscii()
    if verified:
      # Clean up used session
      discard dbExecute("DELETE FROM captcha_sessions WHERE session_id = $1", sessionId)
    
    return verified
  except:
    echo "[ERROR] Failed to verify captcha session: ", getCurrentExceptionMsg()
    return false

# Simple ASCII art captcha generation as fallback
proc generateSimpleCaptcha(text: string): string =
  var lines = @[
    repeat(" ", 40),
    repeat(" ", 40),
    repeat(" ", 40),
    repeat(" ", 40),
    repeat(" ", 40)
  ]
  
  for i, c in text:
    let x = 4 + i * 6
    case c:
    of 'A':
      lines[0][x] = ' '
      lines[1][x] = 'A'
      lines[2][x] = '|'
      lines[3][x] = '|'
      lines[4][x] = ' '
    of 'B'..'Z', '2'..'9':
      lines[1][x] = c
      lines[2][x] = '|'
      lines[3][x] = '|'
    else:
      lines[1][x] = c
  
  result = lines.join("\n")

proc createCaptchaImage(text: string): string =
  # Create a simple SVG image
  let svg = """
<svg width="160" height="60" xmlns="http://www.w3.org/2000/svg">
  <rect width="160" height="60" fill="#f8f9fa" stroke="#dee2e6"/>
  <text x="80" y="35" font-family="monospace" font-size="24" text-anchor="middle" fill="#495057">""" & text & """</text>
  <!-- Add some noise lines -->
  <line x1="10" y1="15" x2="150" y2="45" stroke="#adb5bd" stroke-width="1"/>
  <line x1="30" y1="50" x2="130" y2="10" stroke="#adb5bd" stroke-width="1"/>
</svg>"""
  result = "data:image/svg+xml;base64," & encode(svg)

proc generateCaptcha(): (string, string) =
  let chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
  var text = ""
  for i in 0..5:
    text.add chars[rand(chars.len-1)]
  let imageData = createCaptchaImage(text)
  result = (text, imageData)

routes:
  get "/captcha":
    let ip = request.remoteAddr
    let (text, imageData) = generateCaptcha()
    # Store captcha solution in database with session ID
    let sessionId = storeCaptchaSession(ip, text)
    # Set session ID as cookie for the frontend to use
    setCookie("captcha_session", sessionId, maxAge = 300) # 5 minutes
    setHeader("Content-Type", "image/svg+xml")
    resp Http200, imageData.split(",")[1].decode()
