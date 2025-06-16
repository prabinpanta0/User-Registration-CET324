import nimcrypto, base64, random

const SaltLength = 32

proc generateSalt*(): string =
  # Generate a random salt
  var saltBytes: array[SaltLength, byte]
  for i in 0..<SaltLength:
    saltBytes[i] = byte(rand(256))
  result = encode(saltBytes)

proc hashPassword*(password: string, salt: string): string =
  # Use multiple rounds of SHA256 for password hashing
  var combined = password & salt
  var hash = $sha256.digest(combined)
  
  # Multiple rounds for additional security
  for i in 0..<10000:
    hash = $sha256.digest(hash & salt)
  
  result = encode(hash)

proc verifyPassword*(password, salt, hash: string): bool =
  let computedHash = hashPassword(password, salt)
  result = computedHash == hash
