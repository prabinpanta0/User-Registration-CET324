import json, times, options, base64, strutils
import ./env

proc generateJwtToken*(claims: JsonNode, durationSec: int): string =
  let jwtSecret = getJwtSecret()
  if jwtSecret.len == 0:
    # This case should ideally be handled more gracefully, perhaps at startup.
    # For now, returning an empty string or raising an error.
    echo "[ERROR] JWT_SECRET is not configured. Cannot generate token."
    return ""

  var claimsWithExp = claims
  claimsWithExp["exp"] = % (epochTime().int64 + durationSec.int64)

  try:
    # Simple JWT implementation for now - not cryptographically secure
    # This is a placeholder for development
    let header = %*{"alg": "HS256", "typ": "JWT"}
    let headerStr = encode(($header), safe = true).replace("=", "")
    let claimsStr = encode(($claimsWithExp), safe = true).replace("=", "")
    let signature = "dev_signature" # Placeholder signature
    result = headerStr & "." & claimsStr & "." & signature
  except Exception as e:
    echo "[ERROR] Failed to generate JWT: ", e.msg
    result = ""

proc validateJwtToken*(token: string): Option[JsonNode] =
  let jwtSecret = getJwtSecret()
  if jwtSecret.len == 0:
    echo "[ERROR] JWT_SECRET is not configured. Cannot validate token."
    return none(JsonNode)

  try:
    # Simple JWT validation for development - not cryptographically secure
    let parts = token.split(".")
    if parts.len != 3:
      echo "[INFO] JWT token structure is invalid."
      return none(JsonNode)
    
    # Decode claims (part 1 is header, part 1 is claims, part 2 is signature)
    let claimsJson = decode(parts[1])
    let claims = parseJson(claimsJson)
    
    # Check expiration
    if claims.hasKey("exp"):
      let exp = claims["exp"].getInt()
      if epochTime().int64 >= exp:
        echo "[INFO] JWT token has expired."
        return none(JsonNode)
    
    echo "[INFO] JWT token validation successful (development mode)."
    return some(claims)
  except Exception as e:
    echo "[ERROR] JWT validation failed: ", e.msg
    return none(JsonNode)

when isMainModule:
  # Example usage and tests
  loadEnvFile() # Load .env if present, for JWT_SECRET

  let claims = %*{"user_id": 123, "username": "testuser"}

  echo "Generating token with 60s expiry..."
  let token = generateJwtToken(claims, 60)
  if token.len > 0:
    echo "Generated token: [REDACTED]" # Security: Never log actual tokens

    echo "\nValidating token (should be valid):"
    let validatedClaims = validateJwtToken(token)
    if validatedClaims.isSome():
      echo "Token is valid. Claims: ", $validatedClaims.get()
    else:
      echo "Token validation failed (unexpected)."

    echo "\nWaiting for 2 seconds..."
    sleep(2000) # Sleep for 2 seconds

    # To test expiry, generate a token with very short life
    echo "\nGenerating token with 1s expiry for expiry test..."
    let shortLivedToken = generateJwtToken(claims, 1)
    if shortLivedToken.len > 0:
      echo "Generated short-lived token: [REDACTED]" # Security: Never log actual tokens
      echo "Waiting for 2 seconds to ensure expiry..."
      sleep(2000)
      echo "Validating short-lived token (should be expired):"
      let expiredClaims = validateJwtToken(shortLivedToken)
      if expiredClaims.isNone():
        echo "Token validation failed as expected (expired)."
      else:
        echo "Token validation succeeded (unexpected for expired token). Claims: ", $expiredClaims.get()
    else:
      echo "Failed to generate short-lived token."

    echo "\nValidating a tampered token (should be invalid):"
    let tamperedToken = token & "tamper"
    let tamperedClaims = validateJwtToken(tamperedToken)
    if tamperedClaims.isNone():
      echo "Tampered token validation failed as expected."
    else:
      echo "Tampered token validation succeeded (unexpected). Claims: ", $tamperedClaims.get()

    echo "\nValidating an empty token (should be invalid):"
    let emptyTokenClaims = validateJwtToken("")
    if emptyTokenClaims.isNone():
      echo "Empty token validation failed as expected."
    else:
      echo "Empty token validation succeeded (unexpected). Claims: ", $emptyTokenClaims.get()

  else:
    echo "Failed to generate token."

  # Test with unconfigured secret (remove/comment out JWT_SECRET in .env for this)
  # let oldSecret = getEnv("JWT_SECRET")
  # putEnv("JWT_SECRET", "") # Simulate missing secret
  # echo "\nTesting with empty JWT_SECRET:"
  # let claimsForEmptySecret = %*{"user_id": 789}
  # let tokenWithEmptySecret = generateJwtToken(claimsForEmptySecret, 60)
  # if tokenWithEmptySecret.len == 0:
  #   echo "Token generation failed as expected with empty secret."
  # else:
  #   echo "Token generated with empty secret (unexpected): ", tokenWithEmptySecret
  #   let validationWithEmptySecret = validateJwtToken(tokenWithEmptySecret)
  #   if validationWithEmptySecret.isNone():
  #     echo "Validation with empty secret failed as expected."
  #   else:
  #     echo "Validation with empty secret succeeded (unexpected)."
  # putEnv("JWT_SECRET", oldSecret) # Restore
  echo "JWT utils tests complete."
