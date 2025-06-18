import ../utils/env
import ../db/db
import os

when isMainModule:
  echo "Loading .env file..."
  loadEnvFile()
  
  let dbUrl = getEnv("DB_URL")
  echo "DB_URL: ", dbUrl
  
  echo "Attempting to connect to database..."
  try:
    connectDb()
    echo "Database connection successful!"
    
    # Test a simple operation
    echo "Testing database operation..."
    let testResult = dbGetUserByUsernameOrEmail("nonexistent")
    echo "Test query completed, user ID: ", testResult.id
    
  except Exception as e:
    echo "Database connection failed: ", e.msg
