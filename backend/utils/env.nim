import os, strutils

proc loadEnvFile*(filename = ".env") =
  let currentDir = getCurrentDir()
  let filePath = if filename.isAbsolute: filename else: currentDir / filename

  if not fileExists(filePath):
    return
  for line in lines(filePath):
    let clean = line.strip()
    if clean.len == 0 or clean.startsWith("#"): continue
    let parts = clean.split('=', 1)
    if parts.len == 2:
      let key = parts[0].strip()
      let value = parts[1].strip()
      putEnv(key, value)

proc getJwtSecret*(): string =
  result = getEnv("JWT_SECRET", "") # Default to empty, but should be set in .env or actual env
  if result.len == 0:
    echo "[WARN] JWT_SECRET is not set in environment. This is insecure for production."
    # For development, a default could be used, but it's better to require it.
    # For now, we'll allow it to be empty and let jwt_utils handle it, potentially erroring.
    # Alternatively, raise an error here if critical for startup.
    # raise newException(ValueError, "JWT_SECRET environment variable is not set.")
    result = "a_s3cr3t_d3v3l0pm3nt_k3y_th4t_sh0uld_b3_ch4ng3d" # Fallback for dev if not set
    echo "[WARN] Using a default development JWT_SECRET. THIS IS INSECURE FOR PRODUCTION."

proc getAuditLogEncryptionKey*(): string =
  result = getEnv("AUDIT_LOG_ENCRYPTION_KEY", "")
  if result.len == 0:
    echo "[WARN] AUDIT_LOG_ENCRYPTION_KEY is not set. Audit log sensitive details will not be encrypted or a default key will be used."
    # Provide a default development key. MUST be changed for production.
    # It should be a 32-byte key for AES-256, typically hex-encoded if stored that way,
    # or the raw bytes if the AES proc expects that. Assuming raw string bytes here.
    # For hex, it would be 64 chars. Let's assume raw for now as per common Nim AES examples.
    result = "d3v_4ud1t_k3y_must_b3_32_byt3s!" # Ensure this is 32 bytes if used directly
    if result.len != 32:
      echo "[CRITICAL ERROR] Default AUDIT_LOG_ENCRYPTION_KEY is not 32 bytes. Encryption will fail."
      # Potentially raise error or use a correctly sized default for dev only.
      # Forcing a 32-byte key for development to avoid AES errors.
      result = "12345678901234567890123456789012" # 32 chars/bytes
    echo "[WARN] Using a default development AUDIT_LOG_ENCRYPTION_KEY. THIS IS INSECURE FOR PRODUCTION."