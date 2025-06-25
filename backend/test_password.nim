import strutils, os
import crypto/password

# Simple test to verify password hashing and verification work together
proc testPassword() =
  echo "Testing password hashing and verification..."
  let testPassword = "TestPassword123!"
  
  echo "[TEST] Hashing password: [REDACTED]" # Security: Never log passwords
  let hash = hashPassword(testPassword)
  echo "[TEST] Generated hash: [REDACTED]" # Security: Never log hashes
  
  echo "[TEST] Verifying correct password..."
  let verifyCorrect = verifyPassword(testPassword, hash)
  echo "[TEST] Verification result for correct password: ", verifyCorrect
  
  echo "[TEST] Verifying wrong password..."
  let verifyWrong = verifyPassword("WrongPassword", hash)
  echo "[TEST] Verification result for wrong password: ", verifyWrong
  
  if verifyCorrect and not verifyWrong:
    echo "[TEST] ✅ Password hashing and verification working correctly!"
  else:
    echo "[TEST] ❌ Password hashing and verification NOT working correctly!"

when isMainModule:
  testPassword()
