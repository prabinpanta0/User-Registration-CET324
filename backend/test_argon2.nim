import argon2

echo "Testing argon2 with correct parameters..."

try:
  let password = "test123"
  let salt = "testsalt"
  
  # Use the simple version: argon2(pwd: string; salt: string): hashes
  echo "Trying simple argon2 function..."
  let hash1 = argon2(password, salt)
  echo "Hash 1: ", hash1
  
  # Use the full version: argon2(argon2type, pwd, salt, iterations, memory, threads, hashlen)
  echo "Trying full argon2 function..."
  let hash2 = argon2("argon2id", password, salt, 3'u32, 65536'u32, 1'u32, 32'u32)
  echo "Hash 2: ", hash2
  
except Exception as e:
  echo "Error: ", e.msg
