import nimcrypto, base64, os, strutils
import nimcrypto/sysrand

const SaltLength* = 32 # Export SaltLength
const DefaultPasswordHashRounds = 100_000

proc getPasswordHashRounds(): int =
  let roundsStr = getEnv("PASSWORD_HASH_ROUNDS", $DefaultPasswordHashRounds)
  try:
    result = parseInt(roundsStr)
    if result <= 0: # Ensure positive number of rounds
      result = DefaultPasswordHashRounds
  except ValueError:
    result = DefaultPasswordHashRounds

proc generateSalt*(): string =
  # Generate a random salt
  var saltBytesArr: array[SaltLength, byte]
  discard sysrand.randomBytes(saltBytesArr) # Call with the openArray, discard int return
  result = encode(saltBytesArr)

proc hashPassword*(password: string, salt: string): string =
  # Use multiple rounds of SHA256 for password hashing
  var combined = password & salt
  var hash = $sha256.digest(combined) # nimcrypto's $ operator for digest
  
  let rounds = getPasswordHashRounds()
  # Subtract 1 because the first hash is already done
  for i in 0..<(rounds - 1): # Ensure correct number of iterations
    hash = $sha256.digest(hash & salt)
  
  result = encode(hash)

proc verifyPassword*(password, salt, hash: string): bool =
  let computedHash = hashPassword(password, salt)
  result = computedHash == hash
