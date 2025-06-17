import std/[json, options, times, asyncdispatch]
import jester # For Request object, might be optional if only headers are needed
import ../crypto/aes
import ../db/db
import ./network # For getClientIp
import ./env     # For getAuditLogEncryptionKey

proc logAuditEvent*(
  eventType: string,
  request: Request = nil, # Optional: provide full request for IP/User-Agent
  userId: Option[int] = none[int](),
  clientIpOverride: Option[string] = none[string](), # If request not available but IP is
  userAgentOverride: Option[string] = none[string](), # If request not available but UA is
  sensitiveDetails: JsonNode = nil, # Data to be encrypted
  additionalData: JsonNode = nil  # Non-sensitive data, stored as JSONB
): Future[void] {.async.} =

  var actualClientIp: Option[string] = none[string]()
  var actualUserAgent: Option[string] = none[string]()

  if notisnil(request):
    actualClientIp = some(getClientIp(request))
    actualUserAgent = some(request.headers.getOrDefault("User-Agent", ""))
  else:
    actualClientIp = clientIpOverride
    actualUserAgent = userAgentOverride

  # Prepare general data for JSONB column
  var data = %*{} # Equivalent to newJObject()
  if userId.isSome():
    data["user_id"] = %userId.get()
  if actualClientIp.isSome():
    data["client_ip"] = %actualClientIp.get()
  if actualUserAgent.isSome():
    data["user_agent"] = %actualUserAgent.get()

  if notisnil(additionalData):
    for key, value in additionalData:
      data[key] = value # Merge additionalData

  var dataJsonOpt: Option[JsonNode] = none()
  if data.len > 0:
    dataJsonOpt = some(data)

  var hexIv: Option[string] = none()
  var hexEncryptedDetails: Option[string] = none()

  if notisnil(sensitiveDetails) and sensitiveDetails.kind != JNull:
    let auditKeyStr = getAuditLogEncryptionKey()
    if auditKeyStr.len == AES_KEY_SIZE: # Ensure key is correct size (e.g. 32 bytes for AES-256)
      let auditKeyBytes = cast[seq[byte]](auditKeyStr) # Direct cast if string is raw bytes
      # Or: let auditKeyBytes = keyFromHex(auditKeyStr) # If key in env is hex
      try:
        let (ciphertext, iv) = aesGcmEncrypt(auditKeyBytes, $sensitiveDetails) # Encrypt JSON string
        hexEncryptedDetails = some(ciphertext)
        hexIv = some(iv)
        echo "[AUDIT INFO] Encrypted sensitive details for event: ", eventType
      except Exception as e:
        echo "[AUDIT ERROR] Failed to encrypt sensitive details for event '", eventType, "'. Error: ", e.msg
        # Decide: log without encryption, or skip sensitive part? For now, skipping encrypted part.
    else:
      echo "[AUDIT ERROR] AUDIT_LOG_ENCRYPTION_KEY is not configured correctly (must be ", $AES_KEY_SIZE, " bytes). Sensitive details will not be encrypted for event: ", eventType

  # Insert into database
  let success = await dbInsertAuditLog(
    eventType,
    userId,
    actualClientIp,
    actualUserAgent,
    dataJsonOpt, # Pass Option[JsonNode]
    hexIv,
    hexEncryptedDetails
  )

  if not success:
    echo "[AUDIT ERROR] Failed to insert audit log into database for event: ", eventType
    # Fallback or further error handling if DB logging fails
  else:
    echo "[AUDIT LOGGED] Event: '", eventType, "'"
    if userId.isSome: echo "  UserID: ", userId.get()
    if actualClientIp.isSome: echo "  IP: ", actualClientIp.get()
    if dataJsonOpt.isSome and dataJsonOpt.get().len > 0: echo "  Data: ", $dataJsonOpt.get()
    if hexEncryptedDetails.isSome: echo "  EncryptedDetails: Present"


when isMainModule:
  # Example usage (requires async context and proper setup for DB, env vars)
  proc main() {.async.} =
    loadEnvFile() # Load .env for keys

    # Mock a Jester request if needed, or pass nil
    # var mockRequest: Request # Needs actual Jester setup or a mock

    echo "Testing audit logging..."

    # Example 1: Login success
    var loginData = %*{"username": "testuser", "login_method": "password"}
    var sensitiveLogin = %*{"raw_password_snippet": "pass..."} # Example sensitive data
    await logAuditEvent(
      eventType = "LOGIN_SUCCESS",
      userId = some(1),
      clientIpOverride = some("192.168.1.100"),
      userAgentOverride = some("Test User Agent/1.0"),
      sensitiveDetails = sensitiveLogin,
      additionalData = loginData
    )

    # Example 2: Action with no sensitive details
    var actionData = %*{"action": "view_profile", "profile_id": 123}
    await logAuditEvent(
      eventType = "VIEW_PROFILE",
      userId = some(2),
      clientIpOverride = some("10.0.0.5"),
      additionalData = actionData
    )

    # Example 3: System event, no user, no request
    var systemData = %*{"detail": "Scheduled task completed."}
    await logAuditEvent(
      eventType = "SYSTEM_TASK_COMPLETE",
      additionalData = systemData
    )

    echo "Audit logging tests complete. Check database and console output."

  # To run this example:
  # 1. Ensure DB is configured and `connectDb()` can be called.
  # 2. Set AUDIT_LOG_ENCRYPTION_KEY and potentially AES_KEY in .env or environment.
  # This test won't run automatically but shows usage.
  # waitFor main() # Uncomment if you have a test DB setup for this.
  echo "Audit log module compiled. Run main() for tests (requires DB setup)."
import os, times

const AUDIT_LOG_FILE = "audit.log"

proc logAudit*(event, ip, user: string) =
  let timestamp = $now()
  let msg = event & "," & ip & "," & user & "," & timestamp
  let (enc, iv) = aesEncrypt(msg)  # Uses environment AES_KEY automatically
  let line = enc & ":" & iv & "\n"
  
  # Safely append to file
  try:
    let existingContent = if fileExists(AUDIT_LOG_FILE): readFile(AUDIT_LOG_FILE) else: ""
    writeFile(AUDIT_LOG_FILE, existingContent & line)
  except IOError:
    # If we can't write to audit log, at least don't crash the application
    discard 