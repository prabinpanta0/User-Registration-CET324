import tables, os, strutils
import postgres as pg
import models
import times, random

var captchaStore: Table[string, string]
var dbConn: pg.PPGconn

# Helper function to execute a query and return status
proc execQuery(query: string): bool =
  let res = pg.pqexec(dbConn, cstring(query))
  defer: pg.pqclear(res)
  return pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK

# Helper function to execute a query and return the result
proc execQueryWithResult(query: string): pg.PPGresult =
  result = pg.pqexec(dbConn, cstring(query))

proc setCaptchaForIp*(ip: string, text: string) =
  captchaStore[ip] = text

proc getCaptchaForIp*(ip: string): string =
  if ip in captchaStore:
    captchaStore[ip]
  else:
    ""

proc connectDb*() =
  let dbUrl = getEnv("DB_URL")
  echo "[DB] DB_URL from env: ", dbUrl
  if dbUrl.len == 0:
    raise newException(ValueError, "DB_URL environment variable is not set.")
  try:
    echo "[DB] Connecting to: ", dbUrl
    dbConn = pg.pqconnectdb(cstring(dbUrl))
    let status = pg.pqstatus(dbConn)
    echo "[DB] Connection status: ", status
    if status != pg.CONNECTION_OK:
      let errorMsg = $pg.pqerrorMessage(dbConn)
      echo "[DB ERROR] Connection failed: ", errorMsg
      raise newException(OSError, "Failed to connect to database: " & errorMsg)
    echo "[DB] Connected successfully"
  except Exception as e:
    echo "[DB ERROR] Exception during connection: ", e.msg
    raise newException(OSError, "Failed to connect to the database: " & e.msg)

proc checkDbConnection*(): bool =
  if dbConn == nil:
    echo "[DB ERROR] Database connection pointer is NULL"
    return false
  let status = pg.pqstatus(dbConn)
  if status != pg.CONNECTION_OK:
    echo "[DB ERROR] Database connection status: ", status
    return false
  return true

proc ensureDbConnection*() =
  if not checkDbConnection():
    echo "[DB] Attempting to reconnect to database..."
    connectDb()

proc dbUserExists*(username, email: string): bool =
  try:
    # Ensure database connection is active
    ensureDbConnection()
    
    let query = "SELECT COUNT(*) FROM users WHERE username = '" & username & "' OR email = '" & email & "'"
    let res = pg.pqexec(dbConn, cstring(query))
    defer: pg.pqclear(res)
    
    let status = pg.pqresultStatus(res)
    if status != pg.PGRES_TUPLES_OK:
      echo "[DB ERROR] Failed to check user existence"
      return false  # Assume user doesn't exist if we can't check
    
    let nrows = pg.pqntuples(res)
    if nrows > 0:
      let count = parseInt($pg.pqgetvalue(res, 0, 0))
      return count > 0
    else:
      return false
      
  except Exception as e:
    echo "[DB ERROR] Exception checking user existence: ", e.msg
    return false  # Assume user doesn't exist if we can't check

proc dbInsertUser*(username, email, hash, salt: string): bool =
  try:
    # Ensure database connection is active
    ensureDbConnection()
    
    echo "[DB DEBUG] Attempting to insert user: ", username, " email: ", email
    # Note: This is simplified - in production you'd use parameterized queries
    let query = "INSERT INTO users (username, email, password_hash, password_salt) VALUES ('" & 
                username & "', '" & email & "', '" & hash & "', '" & salt & "')"
    echo "[DB DEBUG] Query: ", query
    
    # Execute query with detailed error reporting
    let res = pg.pqexec(dbConn, cstring(query))
    defer: pg.pqclear(res)
    
    let status = pg.pqresultStatus(res)
    echo "[DB DEBUG] Query status: ", status
    echo "[DB DEBUG] Expected status: ", pg.PGRES_COMMAND_OK
    
    if status != pg.PGRES_COMMAND_OK:
      let errorMsg = $pg.pqerrorMessage(dbConn)
      let resultError = $pg.pqresultErrorMessage(res)
      echo "[DB ERROR] Query failed with status: ", status
      echo "[DB ERROR] Connection error: ", errorMsg
      echo "[DB ERROR] Result error: ", resultError
      result = false
    else:
      result = true
      echo "[DB DEBUG] Query executed successfully"
      
  except Exception as e:
    echo "[DB ERROR] Exception: ", e.msg
    result = false

proc dbGetUserByUsernameOrEmail*(userOrEmail: string): User =
  let query = "SELECT id, username, email, password_hash, password_salt, mfa_enabled, mfa_secret_enc, recovery_codes_enc, last_login FROM users WHERE username = '" & userOrEmail & "' OR email = '" & userOrEmail & "'"
  echo "[DB DEBUG] Query: ", query
  let res = execQueryWithResult(query)
  
  try:
    let status = pg.pqresultStatus(res)
    echo "[DB DEBUG] Query status: ", status
    if status != pg.PGRES_TUPLES_OK:
      echo "[DB DEBUG] Query failed with status: ", status
      return User()  # Return empty user if query failed
    
    let nrows = pg.pqntuples(res)
    echo "[DB DEBUG] Number of rows returned: ", nrows
    if nrows > 0:
      # Get the first row
      result = User(
        id: parseInt($pg.pqgetvalue(res, 0, 0)),
        username: $pg.pqgetvalue(res, 0, 1),
        email: $pg.pqgetvalue(res, 0, 2),
        passwordHash: $pg.pqgetvalue(res, 0, 3),
        passwordSalt: $pg.pqgetvalue(res, 0, 4),
        mfaEnabled: $pg.pqgetvalue(res, 0, 5) == "t",
        mfaSecretEnc: $pg.pqgetvalue(res, 0, 6),
        recoveryCodesEnc: $pg.pqgetvalue(res, 0, 7),
        lastLogin: $pg.pqgetvalue(res, 0, 8)
      )
    else:
      result = User()  # Return empty user if no results
  finally:
    pg.pqclear(res)  # Always free the result

proc dbGetUserById*(userId: int): User =
  let query = "SELECT id, username, email, password_hash, password_salt, mfa_enabled, mfa_secret_enc, recovery_codes_enc, last_login FROM users WHERE id = " & $userId
  let res = execQueryWithResult(query)
  
  try:
    let status = pg.pqresultStatus(res)
    if status != pg.PGRES_TUPLES_OK:
      return User()  # Return empty user if query failed
    
    let nrows = pg.pqntuples(res)
    if nrows > 0:
      # Get the first row
      result = User(
        id: parseInt($pg.pqgetvalue(res, 0, 0)),
        username: $pg.pqgetvalue(res, 0, 1),
        email: $pg.pqgetvalue(res, 0, 2),
        passwordHash: $pg.pqgetvalue(res, 0, 3),
        passwordSalt: $pg.pqgetvalue(res, 0, 4),
        mfaEnabled: $pg.pqgetvalue(res, 0, 5) == "t",
        mfaSecretEnc: $pg.pqgetvalue(res, 0, 6),
        recoveryCodesEnc: $pg.pqgetvalue(res, 0, 7),
        lastLogin: $pg.pqgetvalue(res, 0, 8)
      )
    else:
      result = User()  # Return empty user if no results
  finally:
    pg.pqclear(res)  # Always free the result

proc dbInsertSession*(userId: int, token: string, expiresAt: string): bool =
  try:
    # Convert epoch timestamp to PostgreSQL timestamp
    let query = "INSERT INTO sessions (user_id, session_token, created_at, expires_at) VALUES (" & 
                $userId & ", '" & token & "', now(), to_timestamp(" & expiresAt & "))"
    echo "[DB DEBUG] Inserting session: userId=", userId, " token=", token[0..10], "... expiresAt=", expiresAt
    echo "[DB DEBUG] Session insert query: ", query
    result = execQuery(query)
    echo "[DB DEBUG] Session insert result: ", result
  except Exception as e:
    echo "[DB ERROR] Session insert failed: ", e.msg
    result = false

proc dbGetSessionByToken*(token: string): Session =
  let query = "SELECT id, user_id, session_token, created_at, expires_at FROM sessions WHERE session_token = '" & token & "' AND expires_at > now()"
  echo "[DB DEBUG] Session lookup query: ", query
  let res = execQueryWithResult(query)
  
  try:
    let status = pg.pqresultStatus(res)
    echo "[DB DEBUG] Session query status: ", status
    if status != pg.PGRES_TUPLES_OK:
      echo "[DB DEBUG] Session query failed"
      return Session()
    
    let nrows = pg.pqntuples(res)
    echo "[DB DEBUG] Session query returned ", nrows, " rows"
    if nrows > 0:
      result = Session(
        id: parseInt($pg.pqgetvalue(res, 0, 0)),
        userId: parseInt($pg.pqgetvalue(res, 0, 1)),
        sessionToken: $pg.pqgetvalue(res, 0, 2),
        createdAt: $pg.pqgetvalue(res, 0, 3),
        expiresAt: $pg.pqgetvalue(res, 0, 4)
      )
      echo "[DB DEBUG] Session found: userId=", result.userId, " token=", result.sessionToken[0..10], "..."
    else:
      echo "[DB DEBUG] No valid session found"
      result = Session()
  finally:
    pg.pqclear(res)

proc dbDeleteSession*(token: string): bool =
  try:
    let query = "DELETE FROM sessions WHERE session_token = '" & token & "'"
    result = execQuery(query)
  except:
    result = false

proc dbSetUserMfaSecret*(userId: int, encSecret, iv: string): bool =
  try:
    let query = "UPDATE users SET mfa_secret_enc = '" & encSecret & "', mfa_iv = '" & iv & "' WHERE id = " & $userId
    result = execQuery(query)
  except:
    result = false

proc dbGetUserMfaSecret*(userId: int): (string, string) =
  let query = "SELECT mfa_secret_enc, mfa_iv FROM users WHERE id = " & $userId
  let res = execQueryWithResult(query)
  
  try:
    let status = pg.pqresultStatus(res)
    if status != pg.PGRES_TUPLES_OK:
      return ("", "")
    
    let nrows = pg.pqntuples(res)
    if nrows > 0:
      result = ($pg.pqgetvalue(res, 0, 0), $pg.pqgetvalue(res, 0, 1))
    else:
      result = ("", "")
  finally:
    pg.pqclear(res)

proc dbEnableUserMfa*(userId: int): bool =
  try:
    let query = "UPDATE users SET mfa_enabled = TRUE WHERE id = " & $userId
    result = execQuery(query)
  except:
    result = false

proc dbUpdateUserPassword*(userId: int, hash, salt: string): bool =
  try:
    let query = "UPDATE users SET password_hash = '" & hash & "', password_salt = '" & salt & "' WHERE id = " & $userId
    result = execQuery(query)
  except:
    result = false

proc incrementFailedLogin*(userId: int): bool =
  try:
    let query = "UPDATE users SET failed_login_count = failed_login_count + 1, last_failed_login = now() WHERE id = " & $userId
    result = execQuery(query)
  except:
    result = false

proc resetFailedLogin*(userId: int): bool =
  try:
    let query = "UPDATE users SET failed_login_count = 0 WHERE id = " & $userId
    result = execQuery(query)
  except:
    result = false

proc setLockout*(userId: int, until: string): bool =
  try:
    let query = "UPDATE users SET lockout_until = '" & until & "' WHERE id = " & $userId
    result = execQuery(query)
  except:
    result = false

proc getUserLockoutInfo*(userId: int): (int, string) =
  let query = "SELECT failed_login_count, lockout_until FROM users WHERE id = " & $userId
  let res = execQueryWithResult(query)
  
  try:
    let status = pg.pqresultStatus(res)
    if status != pg.PGRES_TUPLES_OK:
      return (0, "")
    
    let nrows = pg.pqntuples(res)
    if nrows > 0:
      result = (parseInt($pg.pqgetvalue(res, 0, 0)), $pg.pqgetvalue(res, 0, 1))
    else:
      result = (0, "")
  finally:
    pg.pqclear(res)

proc listSessionsForUser*(userId: int): seq[Session] =
  result = @[]
  let query = "SELECT id, user_id, session_token, created_at, expires_at FROM sessions WHERE user_id = " & $userId
  let res = execQueryWithResult(query)
  
  try:
    let status = pg.pqresultStatus(res)
    if status != pg.PGRES_TUPLES_OK:
      return @[]
    
    let nrows = pg.pqntuples(res)
    for i in 0..<nrows:
      result.add(Session(
        id: parseInt($pg.pqgetvalue(res, i, 0)),
        userId: parseInt($pg.pqgetvalue(res, i, 1)),
        sessionToken: $pg.pqgetvalue(res, i, 2),
        createdAt: $pg.pqgetvalue(res, i, 3),
        expiresAt: $pg.pqgetvalue(res, i, 4)
      ))
  finally:
    pg.pqclear(res)

proc deleteSessionById*(sessionId: int): bool =
  try:
    let query = "DELETE FROM sessions WHERE id = " & $sessionId
    result = execQuery(query)
  except:
    result = false

proc createSession*(userId: int): string =
  # Generate a random session token
  randomize()
  var token = ""
  for i in 0..<32:
    token.add char(rand(255))
  
  # Convert to hex string for safe storage
  result = ""
  for c in token:
    result.add toHex(ord(c), 2)
  
  # Set expiration to 24 hours from now
  let expiresAt = $(epochTime().int64 + 86400)
  
  # Store in database
  discard dbInsertSession(userId, result, expiresAt)

proc dbUpdateUserLastLogin*(userId: int): bool =
  try:
    # Store current timestamp in readable format
    let now = times.now()
    let currentTime = now.format("yyyy-MM-dd HH:mm:ss")
    let query = "UPDATE users SET last_login = '" & currentTime & "' WHERE id = " & $userId
    echo "[DB DEBUG] Updating last login for user ", userId, " to ", currentTime
    result = execQuery(query)
    echo "[DB DEBUG] Last login update result: ", result
  except Exception as e:
    echo "[DB ERROR] Failed to update last login: ", e.msg
    result = false

proc dbListUserSessions*(userId: int): seq[Session] =
  result = @[]
  try:
    let query = "SELECT id, user_id, session_token, created_at, expires_at FROM sessions WHERE user_id = " & $userId & " AND expires_at > now() ORDER BY created_at DESC"
    echo "[DB DEBUG] Listing sessions for user ", userId
    let res = execQueryWithResult(query)
    
    try:
      let status = pg.pqresultStatus(res)
      if status != pg.PGRES_TUPLES_OK:
        echo "[DB DEBUG] Session list query failed with status: ", status
        return @[]
      
      let nrows = pg.pqntuples(res)
      echo "[DB DEBUG] Found ", nrows, " active sessions for user ", userId
      
      for i in 0..<nrows:
        let session = Session(
          id: parseInt($pg.pqgetvalue(res, i, 0)),
          userId: parseInt($pg.pqgetvalue(res, i, 1)),
          sessionToken: $pg.pqgetvalue(res, i, 2),
          createdAt: $pg.pqgetvalue(res, i, 3),
          expiresAt: $pg.pqgetvalue(res, i, 4)
        )
        result.add(session)
    finally:
      pg.pqclear(res)
  except Exception as e:
    echo "[DB ERROR] Failed to list user sessions: ", e.msg

proc dbRevokeSession*(sessionId: int): bool =
  try:
    let query = "DELETE FROM sessions WHERE id = " & $sessionId
    echo "[DB DEBUG] Revoking session with ID: ", sessionId
    result = execQuery(query)
    echo "[DB DEBUG] Session revoke result: ", result
  except Exception as e:
    echo "[DB ERROR] Failed to revoke session: ", e.msg
    result = false
