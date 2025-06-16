import jester, json, strutils
import ../db/db
import ../crypto/aes
import ../utils/csrf
import ../crypto/password
import nimcrypto, times, sequtils, random
import ../routes/login

proc generateTotpSecret(): string =
  # Generate a random 20-byte secret and encode as base32
  import random
  randomize()
  var secretBytes = newSeq[byte](20)
  for i in 0..<20:
    secretBytes[i] = byte(rand(255))
  
  # Simple base32 encoding
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  var bits = 0
  var bitBuffer = 0
  result = ""
  
  for b in secretBytes:
    bitBuffer = (bitBuffer shl 8) or b.int
    bits += 8
    while bits >= 5:
      result.add(base32Chars[(bitBuffer shr (bits - 5)) and 0x1F])
      bits -= 5
  
  if bits > 0:
    result.add(base32Chars[(bitBuffer shl (5 - bits)) and 0x1F])

proc base32Decode(s: string): seq[byte] =
  # Simple base32 decoding
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  var charMap: array[256, int]
  for i in 0..<256:
    charMap[i] = -1
  for i, c in base32Chars:
    charMap[c.ord] = i
  
  var bits = 0
  var bitBuffer = 0
  result = @[]
  
  for c in s.toUpperAscii:
    if c == '=':
      break
    let val = charMap[c.ord]
    if val < 0:
      continue
    bitBuffer = (bitBuffer shl 5) or val
    bits += 5
    if bits >= 8:
      result.add(byte((bitBuffer shr (bits - 8)) and 0xFF))
      bits -= 8

proc hotp(secret: seq[byte], counter: int, digits: int = 6): string =
  var msg = newSeq[byte](8)
  for i in 0..7:
    msg[7-i] = byte((counter shr (i*8)) and 0xff)
  let hmac = hmac_sha1(secret, msg)
  let offset = hmac[^1] and 0x0f
  let code = ((hmac[offset].int and 0x7f) shl 24) or
             ((hmac[offset+1].int and 0xff) shl 16) or
             ((hmac[offset+2].int and 0xff) shl 8) or
             (hmac[offset+3].int and 0xff)
  let otp = code mod (10^digits)
  result = otp.intToStr.padLeft('0', digits)

proc totp(secret: string, time: int64 = epochTime().int64, digits: int = 6, period: int = 30): string =
  let key = base32Decode(secret.replace(" ", "").toUpperAscii())
  let counter = time div period
  result = hotp(key, counter, digits)

proc verifyTotp(secret, code: string): bool =
  # Accept codes for current, previous, and next time window
  let now = epochTime().int64
  for offset in -1..1:
    let t = now + offset * 30
    let expectedCode = totp(secret, t)
    if expectedCode == code:
      return true
  return false

routes:
  post "/mfa/setup":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return
    let secret = generateTotpSecret()
    let key = getEnv("AES_KEY")
    let (encSecret, iv) = aesGcmEncrypt(key, secret)
    if not dbSetUserMfaSecret(user.id, encSecret, iv):
      resp Http500, "Failed to store MFA secret."
      return
    # Generate otpauth URL
    let otpauth = "otpauth://totp/SecureApp:" & user.username & "?secret=" & secret & "&issuer=SecureApp"
    # Return data for client-side QR generation
    resp Http200, %*{"otpauth": otpauth, "secret": secret}

  post "/mfa/verify":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return
    let body = parseJson(request.body)
    let code = body["code"].getStr
    let (encSecret, iv) = dbGetUserMfaSecret(user.id)
    let key = getEnv("AES_KEY")
    let secret = aesGcmDecrypt(key, encSecret, iv)
    if not verifyTotp(secret, code):
      resp Http400, "Invalid code."
      return
    if not dbEnableUserMfa(user.id):
      resp Http500, "Failed to enable MFA."
      return
    resp Http200, "MFA enabled."
