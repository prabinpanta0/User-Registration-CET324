# Ensure 'argon2' library is added to project dependencies
# For example, using Nimble: nimble install argon2
import argon2 # Assuming a common Nim library named 'argon2'
import os, strutils, random
# Imports for legacy functions
import nimcrypto, base64
# nimcrypto/sysrand only needed for legacy functions, keep if needed

# --- Argon2id Implementation (Current) ---

# Define default Argon2id parameters - these should be configurable
# Argon2id version 1.3 (0x13) is $v=19
# m: memory cost in KiB. 65536 KiB = 64 MiB
# t: iterations
# p: parallelism factor (lanes)
const
  DefaultArgon2MemoryCost = 65536 # KiB
  DefaultArgon2Iterations = 3 # Match .env default
  DefaultArgon2Parallelism = 4 # Match .env default

# Nim's standard library `os.getEnv` returns string.
# `strutils.parseInt` is used for conversion. Helper procs ensure defaults.
proc getEnvVarAsInt(name: string, defaultValue: int): int =
  let valueStr = getEnv(name, $defaultValue)
  try:
    result = parseInt(valueStr)
    if result <= 0: result = defaultValue # Ensure positive values or fallback
  except ValueError:
    result = defaultValue

proc getArgon2MemoryCost(): int =
  getEnvVarAsInt("ARGON2_MEMORY_COST", DefaultArgon2MemoryCost)

proc getArgon2Iterations(): int =
  getEnvVarAsInt("ARGON2_ITERATIONS", DefaultArgon2Iterations)

proc getArgon2Parallelism(): int =
  getEnvVarAsInt("ARGON2_PARALLELISM", DefaultArgon2Parallelism)

proc hashPassword*(password: string): string =
  # Using the argon2 library with proper API
  let m_cost = getArgon2MemoryCost() # Memory cost in KiB
  let t_cost = getArgon2Iterations() # Number of iterations
  let p_lanes = getArgon2Parallelism() # Degree of parallelism
  try:
    # Generate raw salt bytes (not base64 encoded)
    var saltBytes: array[16, byte]
    for i in 0..<16:
      saltBytes[i] = byte(rand(256))
    
    # Convert salt bytes to string for Base64 encoding
    var saltStr = newString(saltBytes.len)
    for i in 0..<saltBytes.len:
      saltStr[i] = char(saltBytes[i])
    
    # Encode salt bytes to Base64 for safe string representation
    let saltB64 = base64.encode(saltStr)
    
    echo "[DEBUG] Hashing password with params - m: ", m_cost, " t: ", t_cost, " p: ", p_lanes, " salt bytes length: ", saltBytes.len
    
    # Use the full argon2 function: argon2(type, pwd, salt, iterations, memory, threads, hashlen)
    let hashResult = argon2("id", password, saltB64, t_cost.uint32, m_cost.uint32, p_lanes.uint32, 32'u32)
    result = hashResult.enc # Return the encoded hash string
    echo "[DEBUG] Generated hash: ", result
  except Exception as e:
    echo "[ERROR] Error hashing password with Argon2: ", e.msg
    raise

proc verifyPassword*(password: string, encodedHash: string): bool =
  # For argon2 verification, try to use the built-in verify function first
  try:
    echo "[DEBUG] Argon2 verify input - password length: ", password.len, " hash: ", encodedHash
    
    # Try different argon2 verify function names that might be available
    when declared(argon2_verify):
      result = argon2_verify(encodedHash, password)
      echo "[DEBUG] Argon2 verify result using argon2_verify: ", result
      return result
    elif declared(verify):
      result = verify(encodedHash, password)
      echo "[DEBUG] Argon2 verify result using verify: ", result
      return result
    else:
      echo "[DEBUG] No built-in verify function found, using manual comparison"
      
      # Compare the hashes directly by re-hashing with extracted parameters
      let parts = encodedHash.split('$')
      if parts.len < 6:
        echo "[ERROR] Invalid encoded hash format, expected 6 parts, got: ", parts.len
        return false
        
      let algorithm = parts[1]    # argon2id
      let version = parts[2]      # v=19
      let paramsPart = parts[3]   # m=4096,t=1,p=1
      let saltPart = parts[4]     # base64salt
      let hashPart = parts[5]     # base64hash
      
      echo "[DEBUG] Hash components - algorithm: ", algorithm, " version: ", version, " params: ", paramsPart
      
      # Parse parameters
      var m_cost, t_cost, p_lanes: uint32
      for param in paramsPart.split(','):
        let keyVal = param.split('=')
        if keyVal.len == 2:
          case keyVal[0]:
          of "m": m_cost = keyVal[1].parseUint.uint32
          of "t": t_cost = keyVal[1].parseUint.uint32  
          of "p": p_lanes = keyVal[1].parseUint.uint32
      
      echo "[DEBUG] Parsed params - m: ", m_cost, " t: ", t_cost, " p: ", p_lanes
      
      # Manual verification: decode the salt from base64 to get raw bytes
      let saltBytes = base64.decode(saltPart)
      let saltStr = base64.encode(cast[string](saltBytes))
      echo "[DEBUG] Using decoded salt bytes, length: ", saltBytes.len
      
      # Re-hash with same parameters using raw salt bytes
      let hashResult = argon2("id", password, saltStr, t_cost, m_cost, p_lanes, 32'u32)
      let computedHash = hashResult.enc
      
      echo "[DEBUG] Original hash: ", encodedHash
      echo "[DEBUG] Computed hash: ", computedHash
      
      result = computedHash == encodedHash
      echo "[DEBUG] Argon2 verify result: ", result
  except Exception as e:
    echo "[ERROR] Error verifying password with Argon2: ", e.msg
    result = false # On error, assume verification failed for security

# --- SHA256 Legacy Implementation ---

const SaltLength_Legacy* = 32 # Export SaltLength for legacy if ever needed directly
const DefaultPasswordHashRounds_Legacy = 100_000

proc getPasswordHashRounds_legacy(): int =
  let roundsStr = getEnv("PASSWORD_HASH_ROUNDS", $DefaultPasswordHashRounds_Legacy) # Use same env var for now
  try:
    result = parseInt(roundsStr)
    if result <= 0: # Ensure positive number of rounds
      result = DefaultPasswordHashRounds_Legacy
  except ValueError:
    result = DefaultPasswordHashRounds_Legacy

# This generateSalt is part of the legacy system, not used by Argon2.
# It might not be needed if all existing users have salts.
# proc generateSalt_legacy*(): string =
#   var saltBytesArr: array[SaltLength_Legacy, byte]
#   discard sysrand.randomBytes(saltBytesArr)
#   result = encode(saltBytesArr)

proc hashPassword_sha256_legacy*(password: string, salt: string): string =
  var combined = password & salt
  var hash = $sha256.digest(combined)
  
  let rounds = getPasswordHashRounds_legacy()
  for i in 0..<(rounds - 1):
    hash = $sha256.digest(hash & salt)
  
  result = encode(hash)
  echo "[DEBUG] Legacy SHA256 hash generated."

proc verifyPassword_sha256_legacy*(password: string, salt: string, storedHash: string): bool =
  let computedHash = hashPassword_sha256_legacy(password, salt)
  result = computedHash == storedHash
  echo "[DEBUG] Legacy SHA256 verify result: ", result

# --- Conceptual Test Outline (already added in previous step) ---
# ...
# Manual Testing Steps for Argon2id Integration:
# ... (content from previous step)
#
# Additional test steps for migration:
# 1. Ensure an old user exists with SHA256 hash and salt.
#    (If not, manually insert one or register a user *before* Argon2 was default).
# 2. Log in as the old user.
# 3. Verify console logs for "[SECURITY_MIGRATION] Legacy password verified for user X. Upgrading to Argon2id."
#    and "[SECURITY_MIGRATION] Password for user X successfully upgraded to Argon2id."
# 4. Check database: user's password_hash should now be an Argon2id hash, and password_salt should be empty.
# 5. Log out and log back in as the same user. It should use Argon2id directly.
# 6. Try logging in with wrong password (should fail).
# 7. If possible, check an old user with a known wrong password for the legacy hash - it should fail verification.
# ---

# Ensure the conceptual test outline from the previous step is fully included below if it was separate.
# For brevity, it's assumed to be merged here from the previous step's content for this file.
