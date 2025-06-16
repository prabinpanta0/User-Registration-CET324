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
    
    let query = "SELECT COUNT(*) FROM users WHERE username = $1 OR email = $2"
    let params: array[2, cstring] = [username.cstring, email.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, params[0].addr, nil, nil, 0)
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

    let query = "INSERT INTO users (username, email, password_hash, password_salt) VALUES ($1, $2, $3, $4)"
    let params: array[4, cstring] = [username.cstring, email.cstring, hash.cstring, salt.cstring]
    echo "[DB DEBUG] Query: INSERT INTO users (username, email, password_hash, password_salt) VALUES ($1, $2, $3, $4) with params: ", username, ", ", email, ", HASH, SALT"
    
    # Execute query with detailed error reporting
    let res = pg.pqexecParams(dbConn, query.cstring, 4, nil, params[0].addr, nil, nil, 0)
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
  # Ensure database connection is active
  ensureDbConnection()
  let query = "SELECT id, username, email, password_hash, password_salt, mfa_enabled, mfa_secret_enc, mfa_iv, recovery_codes_enc, last_login FROM users WHERE username = $1 OR email = $2"
  let params: array[2, cstring] = [userOrEmail.cstring, userOrEmail.cstring]
  echo "[DB DEBUG] Query: SELECT id, username, email, password_hash, password_salt, mfa_enabled, mfa_secret_enc, mfa_iv, recovery_codes_enc, last_login FROM users WHERE username = $1 OR email = $2 with param: ", userOrEmail

  let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, params[0].addr, nil, nil, 0)
  
  try:
    let status = pg.pqresultStatus(res)
    # Note: The original query was selecting mfa_secret_enc at index 6, and recovery_codes_enc at 7, last_login at 8.
    # With mfa_iv added, these indices shift.
    # Original: id(0), username(1), email(2), password_hash(3), password_salt(4), mfa_enabled(5), mfa_secret_enc(6), recovery_codes_enc(7), last_login(8)
    # New:      id(0), username(1), email(2), password_hash(3), password_salt(4), mfa_enabled(5), mfa_secret_enc(6), mfa_iv(7), recovery_codes_enc(8), last_login(9)
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
        mfaIv: $pg.pqgetvalue(res, 0, 7), # Added mfaIv
        recoveryCodesEnc: $pg.pqgetvalue(res, 0, 8),
        lastLogin: $pg.pqgetvalue(res, 0, 9)
      )
    else:
      result = User()  # Return empty user if no results
  finally:
    pg.pqclear(res)

proc dbGetUserById*(userId: int): User =
  # Ensure database connection is active
  ensureDbConnection()
  let query = "SELECT id, username, email, password_hash, password_salt, mfa_enabled, mfa_secret_enc, mfa_iv, recovery_codes_enc, last_login FROM users WHERE id = $1"
  let userIdStr = $userId
  let params: array[1, cstring] = [userIdStr.cstring]

  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
  
  try:
    let status = pg.pqresultStatus(res)
    if status != pg.PGRES_TUPLES_OK:
      return User()  # Return empty user if query failed
    
    let nrows = pg.pqntuples(res)
    if nrows > 0:
      # Get the first row
      # Indices updated to match the new SELECT query including mfa_iv
      result = User(
        id: parseInt($pg.pqgetvalue(res, 0, 0)),
        username: $pg.pqgetvalue(res, 0, 1),
        email: $pg.pqgetvalue(res, 0, 2),
        passwordHash: $pg.pqgetvalue(res, 0, 3),
        passwordSalt: $pg.pqgetvalue(res, 0, 4),
        mfaEnabled: $pg.pqgetvalue(res, 0, 5) == "t",
        mfaSecretEnc: $pg.pqgetvalue(res, 0, 6),
        mfaIv: $pg.pqgetvalue(res, 0, 7), # Added mfaIv
        recoveryCodesEnc: $pg.pqgetvalue(res, 0, 8),
        lastLogin: $pg.pqgetvalue(res, 0, 9)
      )
    else:
      result = User()  # Return empty user if no results
  finally:
    pg.pqclear(res)

proc dbInsertSession*(userId: int, token: string, expiresAt: string): bool =
  try:
    ensureDbConnection()
    let query = "INSERT INTO sessions (user_id, session_token, created_at, expires_at) VALUES ($1, $2, now(), to_timestamp($3))"
    let userIdStr = $userId
    let params: array[3, cstring] = [userIdStr.cstring, token.cstring, expiresAt.cstring]

    echo "[DB DEBUG] Inserting session: userId=", userId, " token=", token[0..10], "... expiresAt=", expiresAt
    echo "[DB DEBUG] Session insert query: INSERT INTO sessions (user_id, session_token, created_at, expires_at) VALUES ($1, $2, now(), to_timestamp($3))"

    let res = pg.pqexecParams(dbConn, query.cstring, 3, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    echo "[DB DEBUG] Session insert result: ", result
  except Exception as e:
    echo "[DB ERROR] Session insert failed: ", e.msg
    result = false

proc dbGetSessionByToken*(token: string): Session =
  ensureDbConnection()
  let query = "SELECT id, user_id, session_token, created_at, expires_at FROM sessions WHERE session_token = $1 AND expires_at > now()"
  let params: array[1, cstring] = [token.cstring]
  echo "[DB DEBUG] Session lookup query: SELECT id, user_id, session_token, created_at, expires_at FROM sessions WHERE session_token = $1 AND expires_at > now() with param: ", token[0..min(token.len-1, 9)], "..."

  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
  
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
    ensureDbConnection()
    let query = "DELETE FROM sessions WHERE session_token = $1"
    let params: array[1, cstring] = [token.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
  except Exception as e:
    echo "[DB ERROR] dbDeleteSession failed: ", e.msg
    result = false

proc dbSetUserMfaSecret*(userId: int, encSecret, iv: string): bool =
  try:
    ensureDbConnection()
    let query = "UPDATE users SET mfa_secret_enc = $1, mfa_iv = $2 WHERE id = $3"
    let userIdStr = $userId
    let params: array[3, cstring] = [encSecret.cstring, iv.cstring, userIdStr.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 3, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
  except Exception as e:
    echo "[DB ERROR] dbSetUserMfaSecret failed: ", e.msg
    result = false

proc dbGetUserMfaSecret*(userId: int): (string, string) =
  ensureDbConnection()
  let query = "SELECT mfa_secret_enc, mfa_iv FROM users WHERE id = $1"
  let userIdStr = $userId
  let params: array[1, cstring] = [userIdStr.cstring]
  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
  
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
    ensureDbConnection()
    let query = "UPDATE users SET mfa_enabled = TRUE WHERE id = $1"
    let userIdStr = $userId
    let params: array[1, cstring] = [userIdStr.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
  except Exception as e:
    echo "[DB ERROR] dbEnableUserMfa failed: ", e.msg
    result = false

proc dbUpdateUserPassword*(userId: int, hash, salt: string): bool =
  try:
    ensureDbConnection()
    let query = "UPDATE users SET password_hash = $1, password_salt = $2 WHERE id = $3"
    let userIdStr = $userId
    let params: array[3, cstring] = [hash.cstring, salt.cstring, userIdStr.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 3, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
  except Exception as e:
    echo "[DB ERROR] dbUpdateUserPassword failed: ", e.msg
    result = false

proc incrementFailedLogin*(userId: int): bool =
  try:
    ensureDbConnection()
    let query = "UPDATE users SET failed_login_count = failed_login_count + 1, last_failed_login = now() WHERE id = $1"
    let userIdStr = $userId
    let params: array[1, cstring] = [userIdStr.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
  except Exception as e:
    echo "[DB ERROR] incrementFailedLogin failed: ", e.msg
    result = false

proc resetFailedLogin*(userId: int): bool =
  try:
    ensureDbConnection()
    let query = "UPDATE users SET failed_login_count = 0 WHERE id = $1"
    let userIdStr = $userId
    let params: array[1, cstring] = [userIdStr.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
  except Exception as e:
    echo "[DB ERROR] resetFailedLogin failed: ", e.msg
    result = false

proc setLockout*(userId: int, until: string): bool =
  try:
    ensureDbConnection()
    # Assuming 'until' is a string that PostgreSQL can cast to a timestamp, e.g., epoch or ISO 8601
    # If 'until' needs to be to_timestamp($1), then the parameter should be $1.
    # Given it was directly concatenated, it's likely already a formatted string or epoch.
    # For safety with parameterized queries, if it's an epoch, it should be passed as string and then used with to_timestamp($1) in query.
    # If it's already a fully formatted timestamp string like 'YYYY-MM-DD HH:MM:SS', then direct assignment $1 should work.
    # The original query was "UPDATE users SET lockout_until = '" & until & "' WHERE id = " & $userId
    # This implies 'until' is already a string representation suitable for SQL.
    let query = "UPDATE users SET lockout_until = $1 WHERE id = $2"
    let userIdStr = $userId
    let params: array[2, cstring] = [until.cstring, userIdStr.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
  except Exception as e:
    echo "[DB ERROR] setLockout failed: ", e.msg
    result = false

proc getUserLockoutInfo*(userId: int): (int, string) =
  ensureDbConnection()
  let query = "SELECT failed_login_count, lockout_until FROM users WHERE id = $1"
  let userIdStr = $userId
  let params: array[1, cstring] = [userIdStr.cstring]
  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
  
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
  ensureDbConnection()
  let query = "SELECT id, user_id, session_token, created_at, expires_at FROM sessions WHERE user_id = $1"
  let userIdStr = $userId
  let params: array[1, cstring] = [userIdStr.cstring]
  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
  
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
    ensureDbConnection()
    let query = "DELETE FROM sessions WHERE id = $1"
    let sessionIdStr = $sessionId
    let params: array[1, cstring] = [sessionIdStr.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
  except Exception as e:
    echo "[DB ERROR] deleteSessionById failed: ", e.msg
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
    ensureDbConnection()
    # Store current timestamp using PostgreSQL's now() function for consistency
    let query = "UPDATE users SET last_login = now() WHERE id = $1"
    let userIdStr = $userId
    let params: array[1, cstring] = [userIdStr.cstring]
    echo "[DB DEBUG] Updating last login for user ", userId
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    echo "[DB DEBUG] Last login update result: ", result
  except Exception as e:
    echo "[DB ERROR] Failed to update last login: ", e.msg
    result = false

proc dbListUserSessions*(userId: int): seq[Session] =
  result = @[]
  try:
    ensureDbConnection()
    let query = "SELECT id, user_id, session_token, created_at, expires_at FROM sessions WHERE user_id = $1 AND expires_at > now() ORDER BY created_at DESC"
    let userIdStr = $userId
    let params: array[1, cstring] = [userIdStr.cstring]
    echo "[DB DEBUG] Listing sessions for user ", userId
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    
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
    ensureDbConnection()
    let query = "DELETE FROM sessions WHERE id = $1"
    let sessionIdStr = $sessionId
    let params: array[1, cstring] = [sessionIdStr.cstring]
    echo "[DB DEBUG] Revoking session with ID: ", sessionId
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    echo "[DB DEBUG] Session revoke result: ", result
  except Exception as e:
    echo "[DB ERROR] Failed to revoke session: ", e.msg
    result = false

# --- Blocked IP Management ---

proc dbAddBlockedIp*(ipAddress: string, blockedUntilEpoch: string, reason: string): bool =
  try:
    ensureDbConnection()
    # PostgreSQL's to_timestamp() expects a double precision Unix epoch value.
    let query = "INSERT INTO blocked_ips (ip_address, blocked_until, reason) VALUES ($1, to_timestamp($2::double precision), $3) ON CONFLICT (ip_address) DO UPDATE SET blocked_until = EXCLUDED.blocked_until, reason = EXCLUDED.reason"
    let params: array[3, cstring] = [ipAddress.cstring, blockedUntilEpoch.cstring, reason.cstring]

    echo "[DB DEBUG] Adding/Updating blocked IP: ", ipAddress, " until epoch: ", blockedUntilEpoch, " for reason: ", reason
    let res = pg.pqexecParams(dbConn, query.cstring, 3, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)

    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
      echo "[DB ERROR] dbAddBlockedIp failed: ", $pg.pqerrorMessage(dbConn)
      let resultError = $pg.pqresultErrorMessage(res)
      if resultError.len > 0: echo "[DB ERROR] Result error: ", resultError
    echo "[DB DEBUG] dbAddBlockedIp result: ", result

  except Exception as e:
    echo "[DB ERROR] Exception in dbAddBlockedIp: ", e.msg
    result = false

proc dbGetBlockedIp*(ipAddress: string): BlockedIp =
  try:
    ensureDbConnection()
    # Select only if not expired
    let query = "SELECT ip_address, extract(epoch from blocked_until)::text, reason FROM blocked_ips WHERE ip_address = $1 AND blocked_until > now()"
    let params: array[1, cstring] = [ipAddress.cstring]

    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)

    if pg.pqresultStatus(res) == pg.PGRES_TUPLES_OK and pg.pqntuples(res) > 0:
      result = BlockedIp(
        ipAddress: $pg.pqgetvalue(res, 0, 0),
        blockedUntil: $pg.pqgetvalue(res, 0, 1), # This is now an epoch string
        reason: $pg.pqgetvalue(res, 0, 2)
      )
    else:
      # Check for errors other than no rows
      if pg.pqresultStatus(res) != pg.PGRES_TUPLES_OK and pg.pqcmdTuples(res) == "0": # No rows is fine
          echo "[DB ERROR] dbGetBlockedIp query failed: ", $pg.pqerrorMessage(dbConn)
          let resultError = $pg.pqresultErrorMessage(res)
          if resultError.len > 0: echo "[DB ERROR] Result error: ", resultError
      result = BlockedIp(ipAddress: "") # Return empty/default if not found or error

  except Exception as e:
    echo "[DB ERROR] Exception in dbGetBlockedIp: ", e.msg
    result = BlockedIp(ipAddress: "")

proc dbRemoveBlockedIp*(ipAddress: string): bool =
  try:
    ensureDbConnection()
    let query = "DELETE FROM blocked_ips WHERE ip_address = $1"
    let params: array[1, cstring] = [ipAddress.cstring]

    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, params[0].addr, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
        echo "[DB ERROR] dbRemoveBlockedIp failed for IP ", ipAddress, ": ", $pg.pqerrorMessage(dbConn)
        let resultError = $pg.pqresultErrorMessage(res)
        if resultError.len > 0: echo "[DB ERROR] Result error: ", resultError

  except Exception as e:
    echo "[DB ERROR] Exception in dbRemoveBlockedIp for IP ", ipAddress, ": ", e.msg
    result = false

proc dbRemoveExpiredBlockedIps*(): bool =
  try:
    ensureDbConnection()
    let query = "DELETE FROM blocked_ips WHERE blocked_until <= now()"
    # No parameters needed for this query
    let res = pg.pqexecParams(dbConn, query.cstring, 0, nil, nil, nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
        echo "[DB ERROR] dbRemoveExpiredBlockedIps failed: ", $pg.pqerrorMessage(dbConn)
        let resultError = $pg.pqresultErrorMessage(res)
        if resultError.len > 0: echo "[DB ERROR] Result error: ", resultError
    else:
        # pqcmdTuples returns the number of rows affected for DELETE/UPDATE
        let rowsAffected = $pg.pqcmdTuples(res)
        echo "[DB DEBUG] dbRemoveExpiredBlockedIps removed ", rowsAffected, " rows."

  except Exception as e:
    echo "[DB ERROR] Exception in dbRemoveExpiredBlockedIps: ", e.msg
    result = false
