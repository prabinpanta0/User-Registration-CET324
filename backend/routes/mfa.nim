import jester, json, strutils
import ../db/db
import ../crypto/aes
import ../utils/csrf
import ../crypto/password
import nimcrypto, times, sequtils, random # nimcrypto for hmac_sha1, times for epochTime, random for rand in generateTotpSecret (now in utils)
import ../routes/login
import ../utils/totp_utils # Import the new utility module
import ../utils/rate_limit # Import for rate limiting

# Rate Limiting Configurations for MFA
const mfaSetupConfig = RateLimitConfig(
  routeIdentifier: "mfa_initial_setup",
  maxAttemptsShortTerm: 3,        # Max 3 setup attempts (generation of new secret)
  windowSecShortTerm: 600,      # within a 10-minute window by an authenticated user
  blockDurationSecLongTerm: 3600  # Long-term DB block for 1 hour if limit exceeded
)

const mfaInitialVerifyConfig = RateLimitConfig(
  routeIdentifier: "mfa_initial_verify",
  maxAttemptsShortTerm: 5,        # Max 5 verification attempts for the newly generated secret
  windowSecShortTerm: 120,      # within a 2-minute window
  blockDurationSecLongTerm: 1800  # Long-term DB block for 30 minutes if limit exceeded
)

routes:
  post "/mfa/setup":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    let ip = "127.0.0.1" # TODO: Get real IP address from request
    if not isRequestAllowed(ip, mfaSetupConfig):
      resp Http429, "Too many MFA setup attempts. Please try later."
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

    let ip = "127.0.0.1" # TODO: Get real IP address from request
    if not isRequestAllowed(ip, mfaInitialVerifyConfig):
      resp Http429, "Too many MFA verification attempts. Please try later."
      return

    let body = parseJson(request.body)
    let code = body["code"].getStr
    let (encSecret, iv) = dbGetUserMfaSecret(user.id)
    let key = getEnv("AES_KEY")
    let secret = aesGcmDecrypt(key, encSecret, iv)
    if not verifyTotp(secret, code, 30, 1): # Explicitly pass default period and window
      resp Http400, "Invalid code."
      return
    if not dbEnableUserMfa(user.id):
      resp Http500, "Failed to enable MFA."
      return
    resp Http200, "MFA enabled."
