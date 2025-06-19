import os, strutils

proc loadEnvFile*(filename = ".env") =
  let currentDir = getCurrentDir()
  var filePath = if filename.isAbsolute: filename else: currentDir / filename

  # If .env not found in current directory, check parent directory
  if not fileExists(filePath):
    let parentDir = currentDir.parentDir()
    filePath = parentDir / filename
  
  if not fileExists(filePath):
    echo "[WARN] Environment file not found: ", filePath
    return
    
  echo "[INFO] Loading environment from: ", filePath
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

proc getHCaptchaSecretKey*(): string =
  result = getEnv("HCAPTCHA_SECRET_KEY", "")
  if result.len == 0:
    echo "[WARN] HCAPTCHA_SECRET_KEY is not set in environment. Captcha verification will fail."

proc getRecaptchaV3SecretKey*(): string =
  result = getEnv("RECAPTCHA_V3_SECRET_KEY", "")
  if result.len == 0:
    echo "[WARN] RECAPTCHA_V3_SECRET_KEY is not set in environment. reCAPTCHA v3 verification will fail."

proc getRecaptchaV3ScoreThreshold*(): float =
  let thresholdStr = getEnv("RECAPTCHA_V3_SCORE_THRESHOLD", "0.5")
  try:
    result = parseFloat(thresholdStr)
  except ValueError:
    echo "[WARN] Invalid RECAPTCHA_V3_SCORE_THRESHOLD value. Using default 0.5"
    result = 0.5