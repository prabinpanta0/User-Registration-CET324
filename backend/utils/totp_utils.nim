import strutils, times, random, sequtils
import nimcrypto/[hmac, sha]
# import endians # Not directly used, but often good for byte manipulation if needed elsewhere
# nimcrypto/utils might not be needed if padLeft from strutils is used.

proc generateTotpSecret*(): string =
  # Generate a random 20-byte secret and encode as base32
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

proc base32Decode*(s: string): seq[byte] =
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
    # TODO: Consider raising an error for invalid characters instead of skipping
    if val < 0:
      continue # Or raise newException(ValueError, "Invalid character in base32 string")
    bitBuffer = (bitBuffer shl 5) or val
    bits += 5
    if bits >= 8:
      result.add(byte((bitBuffer shr (bits - 8)) and 0xFF))
      bits -= 8

proc hotp*(secret: seq[byte], counter: int, digits: int = 6): string =
  var msg = newSeq[byte](8)
  # Pack counter into 8-byte big-endian sequence
  for i in 0..7:
    msg[7-i] = byte((counter shr (i*8)) and 0xff)

  let hmacResult = hmac(sha1, secret, msg)
  let hmacBytes = hmacResult.data

  # Dynamic truncation (RFC 4226)
  let offset = hmacBytes[^1] and 0x0f # Last nibble of HMAC
  let code = ((hmacBytes[offset].int and 0x7f) shl 24) or
             ((hmacBytes[offset+1].int and 0xff) shl 16) or
             ((hmacBytes[offset+2].int and 0xff) shl 8) or
             (hmacBytes[offset+3].int and 0xff)

  # Calculate modulo using power of 10
  var modulus = 1
  for i in 0..<digits:
    modulus *= 10
  let otp = code mod modulus # Resulting OTP
  result = $otp
  # Pad with zeros if needed
  while result.len < digits:
    result = "0" & result

proc totp*(secret: string, time: int64 = epochTime().int64, digits: int = 6, period: int = 30): string =
  # Ensure secret is uppercase and remove spaces for base32 decoding
  let key = base32Decode(secret.replace(" ", "").toUpperAscii())
  let counter = time div period
  result = hotp(key, counter.int, digits)

proc verifyTotp*(secret: string, code: string, period: int = 30, window: int = 1): bool =
  # Accept codes for current, previous, and next time windows (window = 1 means -1, 0, +1 periods)
  let now = epochTime().int64
  echo "[DEBUG] TOTP Verify - Input code: '", code, "' secret length: ", secret.len
  for offset in -window..window:
    let t = now + offset * period
    let expectedCode = totp(secret, t, 6, period) # Fixed to always use 6 digits
    echo "[DEBUG] TOTP Verify - Expected code for offset ", offset, ": '", expectedCode, "'"
    if expectedCode == code:
      echo "[DEBUG] TOTP Verify - MATCH found at offset ", offset
      return true
  echo "[DEBUG] TOTP Verify - NO MATCH found"
  return false
