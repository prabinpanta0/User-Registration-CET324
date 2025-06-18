import ../utils/env
import os

when isMainModule:
  echo "Loading .env file..."
  loadEnvFile()
  
  let dbUrl = getEnv("DB_URL")
  echo "DB_URL: ", if dbUrl.len > 0: dbUrl else: "NOT SET"
  
  let aesKey = getEnv("AES_KEY")
  echo "AES_KEY: ", if aesKey.len > 0: "SET (length=" & $aesKey.len & ")" else: "NOT SET"
  
  let port = getEnv("PORT", "DEFAULT")
  echo "PORT: ", port
