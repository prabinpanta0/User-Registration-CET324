import strutils, random, sets
import nimcrypto/sha2
import base64 # For encoding the hash

const
  RecoveryCodeLength = 10
  NumberOfRecoveryCodes = 10
  RecoveryCodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

proc generateSingleRecoveryCode(): string =
  var code = newString(RecoveryCodeLength)
  for i in 0..<RecoveryCodeLength:
    code[i] = RecoveryCodeChars[rand(RecoveryCodeChars.high)]
  return code

proc hashRecoveryCode*(code: string): string {.gcsafe.} =
  # Hashes a single recovery code using SHA256.
  # Note: Argon2id would be preferred for stronger hashing if resources allow.
  # For this implementation, SHA256 is used as specified.
  # No salt is used here for individual codes, relying on the code's randomness.
  # If salting were added, a per-user salt stored separately or a global pepper might be considered.
  let hashedCode = sha256.digest(code)
  result = encode(hashedCode.data) # base64 encode the raw hash bytes

proc generateRecoveryCodes*(): (seq[string], seq[string]) =
  # Generates a list of plaintext recovery codes and their corresponding hashed versions.
  # Returns: (plaintextCodes, hashedCodes)
  var
    plaintextCodes = newSeq[string]()
    hashedCodes = newSeq[string]()
    generatedCodes = initHashSet[string]() # To ensure uniqueness

  while plaintextCodes.len < NumberOfRecoveryCodes:
    let newCode = generateSingleRecoveryCode()
    if not generatedCodes.contains(newCode):
      generatedCodes.incl(newCode)
      plaintextCodes.add(newCode)
      hashedCodes.add(hashRecoveryCode(newCode))

  return (plaintextCodes, hashedCodes)

when isMainModule:
  # Example usage:
  randomize() # Ensure random seed
  let (plain, hashed) = generateRecoveryCodes()
  echo "Generated ", plain.len, " plaintext recovery codes"
  echo "Generated ", hashed.len, " hashed recovery codes"
  echo "Sample hash test completed"
