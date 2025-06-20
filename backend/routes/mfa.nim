import jester, json, strutils, random # Added random for randomize()
import ../db/db
import ../crypto/aes
# import ../utils/csrf # Removed this, assuming it's replaced by csrf_validator
import ../utils/csrf_validator # Added new CSRF validator
import ../crypto/password
import nimcrypto, times, sequtils # nimcrypto for hmac_sha1, times for epochTime
import ../routes/login
import ../utils/totp_utils # Import the new utility module
import ../utils/mfa_recovery_utils # Import for recovery codes
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

    # CSRF Check (session-bound)
    if not verifyCsrf(request):
      resp Http403, "CSRF token validation failed."
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
    echo "[MFA VERIFY] Route called"
    let user = getCurrentUser(request)
    if user.id == 0:
      echo "[MFA VERIFY] Not authenticated"
      resp Http401, "Not authenticated."
      return

    # CSRF Check (session-bound)
    if not verifyCsrf(request):
      resp Http403, "CSRF token validation failed."
      return

    let ip = "127.0.0.1" # TODO: Get real IP address from request
    if not isRequestAllowed(ip, mfaInitialVerifyConfig):
      echo "[MFA VERIFY] Rate limited"
      resp Http429, "Too many MFA verification attempts. Please try later."
      return

    let body = parseJson(request.body)
    let code = body["code"].getStr
    echo "[MFA VERIFY] Code entered: '", code, "' length: ", code.len
    
    # Validate code format
    if code.len != 6:
      echo "[MFA VERIFY] ERROR: Invalid code length"
      resp Http400, "Invalid code format. Must be 6 digits."
      return
    
    # Check if code is all digits
    for c in code:
      if not c.isDigit:
        echo "[MFA VERIFY] ERROR: Non-digit character in code"
        resp Http400, "Invalid code format. Must be 6 digits."
        return
    let (encSecret, iv) = dbGetUserMfaSecret(user.id)
    echo "[MFA VERIFY] Raw encrypted secret length: ", encSecret.len, " IV length: ", iv.len
    
    if encSecret.len == 0 or iv.len == 0:
      echo "[MFA VERIFY] ERROR: No MFA secret found for user"
      resp Http500, "MFA not set up properly."
      return
    
    let key = getEnv("AES_KEY")
    let secret = aesGcmDecrypt(key, encSecret, iv)
    echo "[MFA VERIFY] Secret decrypted, length: ", secret.len
    
    if secret.len == 0:
      echo "[MFA VERIFY] ERROR: Failed to decrypt MFA secret"
      resp Http500, "MFA decryption failed."
      return
    
    if not verifyTotp(secret, code, 30, 1): # Explicitly pass default period and window
      echo "[MFA VERIFY] Code verification FAILED"
      resp Http400, "Invalid code."
      return
    echo "[MFA VERIFY] Code verification SUCCESS"
    if not dbEnableUserMfa(user.id):
      echo "[MFA VERIFY] Failed to enable MFA in database"
      resp Http500, "Failed to enable MFA."
      return
    echo "[MFA VERIFY] MFA enabled successfully for user ID: ", user.id

    # Generate and store recovery codes
    randomize() # Ensure random is seeded before generating codes
    let (plaintextCodes, hashedCodes) = generateRecoveryCodes()
    if not dbSetUserRecoveryCodes(user.id, hashedCodes):
      # Log the error, but MFA is already enabled.
      # This is not ideal, user won't have recovery codes.
      # Consider how to handle this case: maybe disable MFA again if codes can't be set?
      # For now, log and proceed.
      echo "[ERROR][MFA_RECOVERY] Failed to store recovery codes for user ID: ", user.id
      # Potentially inform the user that recovery code generation failed.
      # For this iteration, the success response won't include them if saving failed.
      resp Http200, %*{"status": "mfa_enabled", "message": "MFA enabled, but recovery code generation failed. Please contact support."}
      return

    echo "[MFA_RECOVERY] Successfully generated and stored recovery codes for user ID: ", user.id

    var responseJson = %*{
      "status": "mfa_enabled",
      "message": "MFA enabled successfully.",
      "recovery_codes": newJArray()
    }
    for code in plaintextCodes:
      responseJson["recovery_codes"].add(newJString(code))

    resp Http200, $responseJson

  get "/mfa/setup":
    let user = getCurrentUser(request)
    if user.id == 0:
      resp Http401, "Not authenticated."
      return

    # If MFA is already enabled, redirect to dashboard
    if user.mfaEnabled:
      resp Http200, %*{
        "status": "already_enabled",
        "message": "MFA is already enabled for this account.",
        "redirect": "/dashboard"
      }
      return

    # Return setup page info - the frontend will handle generating QR code
    resp Http200, %*{
      "status": "setup_required",
      "message": "Please set up MFA to secure your account.",
      "username": user.username
    }
