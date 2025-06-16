import random, strutils, sequtils, jester, base64
import ../db/db
import ../utils/audit_log

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
    # Store the captcha text in a session or database for verification
    # For now, we'll store it in a simple way
    # TODO: Implement proper session storage
    setHeader("Content-Type", "image/svg+xml")
    resp Http200, imageData.split(",")[1].decode()
