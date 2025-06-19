import tables, os, strutils, options
import postgres as pg
import models
import times, random
import json
import asyncdispatch
import options

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
    let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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
    
    echo "[DB DEBUG] Attempting to insert user: ", username
    let query = "INSERT INTO users (username, email, password_hash, password_salt, password_history, password_last_changed) VALUES ($1, $2, $3, $4, '[]'::jsonb, NOW())"
    let params: array[4, cstring] = [username.cstring, email.cstring, hash.cstring, salt.cstring]
    
    # Execute query with detailed error reporting
    let res = pg.pqexecParams(dbConn, query.cstring, 4, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)
    
    let status = pg.pqresultStatus(res)
    
    if status != pg.PGRES_COMMAND_OK:
      let errorMsg = $pg.pqresultErrorMessage(res)
      echo "[DB ERROR] Insert failed: ", errorMsg
      result = false
    else:
      result = true
      echo "[DB DEBUG] User inserted successfully"
      
  except Exception as e:
    echo "[DB ERROR] Exception: ", e.msg
    result = false

proc dbSetUserRecoveryCodes*(userId: int, hashedCodes: seq[string]): bool =
  # Stores hashed recovery codes as a JSON array string.
  # Note: The column is named recovery_codes_enc, but we are storing hashes.
  # This could be renamed to recovery_codes_hashed in a future schema migration for clarity.
  try:
    ensureDbConnection()
    var codesJsonArray = newJArray()
    for codeHash in hashedCodes:
      codesJsonArray.add(newJString(codeHash))
    let codesJsonString = $codesJsonArray

    let query = "UPDATE users SET recovery_codes_enc = $1 WHERE id = $2"
    let userIdStr = $userId
    let params: array[2, cstring] = [codesJsonString.cstring, userIdStr.cstring]

    echo "[DB DEBUG] Setting recovery codes for user ID ", userId
    let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)

    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
      echo "[DB ERROR] dbSetUserRecoveryCodes failed for user ID ", userId, ": ", $pg.pqerrorMessage(dbConn)
      let resultError = $pg.pqresultErrorMessage(res)
      if resultError.len > 0: echo "[DB ERROR] Result error: ", resultError
    else:
      echo "[DB DEBUG] Successfully set recovery codes for user ID ", userId

  except Exception as e:
    echo "[DB ERROR] Exception in dbSetUserRecoveryCodes for user ID ", userId, ": ", e.msg
    result = false

proc dbGetUserRecoveryCodes*(userId: int): seq[string] =
  # Retrieves and parses the JSON array of hashed recovery codes for a user.
  result = @[]
  try:
    ensureDbConnection()
    let query = "SELECT recovery_codes_enc FROM users WHERE id = $1"
    let userIdStr = $userId
    let params: array[1, cstring] = [userIdStr.cstring]

    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)

    if pg.pqresultStatus(res) == pg.PGRES_TUPLES_OK and pg.pqntuples(res) > 0:
      let codesJsonString = $pg.pqgetvalue(res, 0, 0)
      if codesJsonString.len > 2 and pg.pqgetisnull(res,0,0) == 0: # Not empty '[]' and not NULL
        try:
          let parsedJson = parseJson(codesJsonString)
          if parsedJson.kind == JArray:
            for item in parsedJson:
              result.add(item.getStr())
          else:
            echo "[DB ERROR] recovery_codes_enc for user ID ", userId, " is not a JSON array: ", codesJsonString
        except JsonParsingError as e:
          echo "[DB ERROR] Failed to parse recovery_codes_enc JSON for user ID ", userId, ": ", codesJsonString, " Error: ", e.msg
      else:
        echo "[DB DEBUG] No recovery codes found or field is empty/null for user ID ", userId
    else:
      if pg.pqresultStatus(res) != pg.PGRES_TUPLES_OK: # Log if it's an actual query error
          echo "[DB ERROR] dbGetUserRecoveryCodes query failed for user ID ", userId, ": ", $pg.pqerrorMessage(dbConn)
          let resultError = $pg.pqresultErrorMessage(res)
          if resultError.len > 0: echo "[DB ERROR] Result error: ", resultError

  except Exception as e:
    echo "[DB ERROR] Exception in dbGetUserRecoveryCodes for user ID ", userId, ": ", e.msg
  # Ensure result is always a sequence, even if empty on error or no codes
  if result.len == 0: result = @[]


proc dbUpdateUserRecoveryCodes*(userId: int, updatedHashedCodes: seq[string]): bool =
  # This function is essentially the same as dbSetUserRecoveryCodes.
  # It updates the stored recovery codes with a new list.
  # If an empty sequence is passed, it will effectively clear the codes.
  # Re-using dbSetUserRecoveryCodes for this purpose.
  # A comment in dbSetUserRecoveryCodes already notes its usage for storing hashed codes.
  echo "[DB DEBUG] Calling dbSetUserRecoveryCodes as dbUpdateUserRecoveryCodes for user ID ", userId
  result = dbSetUserRecoveryCodes(userId, updatedHashedCodes)


proc dbGetUserByUsernameOrEmail*(userOrEmail: string): User =
  # Ensure database connection is active
  ensureDbConnection()
  let query = "SELECT id, username, email, password_hash, password_salt, mfa_enabled, mfa_secret_enc, mfa_iv, recovery_codes_enc, last_login, password_history, to_char(password_last_changed, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as password_last_changed, is_verified FROM users WHERE username = $1 OR email = $2"
  let params: array[2, cstring] = [userOrEmail.cstring, userOrEmail.cstring]
  echo "[DB DEBUG] Query: SELECT id, username, email, password_hash, password_salt, mfa_enabled, mfa_secret_enc, mfa_iv, recovery_codes_enc, last_login, password_history, to_char(password_last_changed, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as password_last_changed, is_verified FROM users WHERE username = $1 OR email = $2 with param: ", userOrEmail

  let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
  
  try:
    let status = pg.pqresultStatus(res)
    # Indices: id(0), username(1), email(2), password_hash(3), password_salt(4), mfa_enabled(5),
    #          mfa_secret_enc(6), mfa_iv(7), recovery_codes_enc(8), last_login(9),
    #          password_history(10), password_last_changed(11), is_verified(12)
    echo "[DB DEBUG] Query status: ", status
    if status != pg.PGRES_TUPLES_OK:
      echo "[DB DEBUG] Query failed with status: ", status
      return User()  # Return empty user if query failed
    
    let nrows = pg.pqntuples(res)
    echo "[DB DEBUG] Number of rows returned: ", nrows
    if nrows > 0:
      var history: seq[string]
      let historyJson = $pg.pqgetvalue(res, 0, 10)
      if historyJson.len > 2: # Not empty '[]'
        try:
          # Assuming JSON strings are directly in the array, e.g., ["hash1", "hash2"]
          # This requires parsing the JSON array string. Nim's std/json can parse this.
          let parsedHistory = parseJson(historyJson)
          for item in parsedHistory:
            history.add(item.getStr())
        except JsonParsingError:
          echo "[DB ERROR] Failed to parse password_history JSON: ", historyJson

      result = User(
        id: parseInt($pg.pqgetvalue(res, 0, 0)),
        username: $pg.pqgetvalue(res, 0, 1),
        email: $pg.pqgetvalue(res, 0, 2),
        passwordHash: $pg.pqgetvalue(res, 0, 3),
        passwordSalt: $pg.pqgetvalue(res, 0, 4),
        mfaEnabled: $pg.pqgetvalue(res, 0, 5) == "t",
        mfaSecretEnc: $pg.pqgetvalue(res, 0, 6),
        mfaIv: $pg.pqgetvalue(res, 0, 7),
        recoveryCodesEnc: $pg.pqgetvalue(res, 0, 8),
        lastLogin: $pg.pqgetvalue(res, 0, 9),
        passwordHistory: history,
        passwordLastChanged: $pg.pqgetvalue(res, 0, 11),
        isVerified: $pg.pqgetvalue(res, 0, 12) == "t"
      )
    else:
      result = User()  # Return empty user if no results
  finally:
    pg.pqclear(res)

proc dbGetUserById*(userId: int): User =
  # Ensure database connection is active
  ensureDbConnection()
  let query = "SELECT id, username, email, password_hash, password_salt, mfa_enabled, mfa_secret_enc, mfa_iv, recovery_codes_enc, last_login, password_history, to_char(password_last_changed, 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as password_last_changed, is_verified FROM users WHERE id = $1"
  let userIdStr = $userId
  let params: array[1, cstring] = [userIdStr.cstring]

  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
  
  try:
    let status = pg.pqresultStatus(res)
    if status != pg.PGRES_TUPLES_OK:
      return User()  # Return empty user if query failed
    
    let nrows = pg.pqntuples(res)
    if nrows > 0:
      var history: seq[string]
      let historyJson = $pg.pqgetvalue(res, 0, 10)
      if historyJson.len > 2: # Not empty '[]'
        try:
          let parsedHistory = parseJson(historyJson)
          for item in parsedHistory:
            history.add(item.getStr())
        except JsonParsingError:
          echo "[DB ERROR] Failed to parse password_history JSON: ", historyJson

      # Indices: id(0)...password_last_changed(11), is_verified(12)
      result = User(
        id: parseInt($pg.pqgetvalue(res, 0, 0)),
        username: $pg.pqgetvalue(res, 0, 1),
        email: $pg.pqgetvalue(res, 0, 2),
        passwordHash: $pg.pqgetvalue(res, 0, 3),
        passwordSalt: $pg.pqgetvalue(res, 0, 4),
        mfaEnabled: $pg.pqgetvalue(res, 0, 5) == "t",
        mfaSecretEnc: $pg.pqgetvalue(res, 0, 6),
        mfaIv: $pg.pqgetvalue(res, 0, 7),
        recoveryCodesEnc: $pg.pqgetvalue(res, 0, 8),
        lastLogin: $pg.pqgetvalue(res, 0, 9),
        passwordHistory: history,
        passwordLastChanged: $pg.pqgetvalue(res, 0, 11),
        isVerified: $pg.pqgetvalue(res, 0, 12) == "t"
      )
    else:
      result = User()  # Return empty user if no results
  finally:
    pg.pqclear(res)

proc dbInsertSession*(userId: int, token: string, expiresAt: string, csrfToken: string = ""): bool =
  try:
    ensureDbConnection()
    # Initialize csrf_token to empty string if not provided, or use provided value
    let query = "INSERT INTO sessions (user_id, session_token, created_at, expires_at, csrf_token) VALUES ($1, $2, now(), to_timestamp($3), $4)"
    let userIdStr = $userId
    let tokenCstr = token.cstring
    let expiresAtCstr = expiresAt.cstring
    let csrfTokenCstr = csrfToken.cstring
    let cParams: array[4, cstring] = [userIdStr.cstring, tokenCstr, expiresAtCstr, csrfTokenCstr]

    echo "[DB DEBUG] Inserting session: userId=", userId, " token=", token[0..10], "... expiresAt=", expiresAt, " csrf_token=", csrfToken
    echo "[DB DEBUG] Session insert query: INSERT INTO sessions (user_id, session_token, created_at, expires_at, csrf_token) VALUES ($1, $2, now(), to_timestamp($3), $4)"

    let res = pg.pqexecParams(dbConn, query.cstring, 4, nil, cast[cstringArray](cParams[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    echo "[DB DEBUG] Session insert result: ", result
  except Exception as e:
    echo "[DB ERROR] Session insert failed: ", e.msg
    result = false

proc dbGetSessionByToken*(token: string): Session =
  ensureDbConnection()
  let query = "SELECT id, user_id, session_token, created_at, expires_at, csrf_token FROM sessions WHERE session_token = $1 AND expires_at > now()"
  let params: array[1, cstring] = [token.cstring]
  echo "[DB DEBUG] Session lookup query: SELECT id, user_id, session_token, created_at, expires_at, csrf_token FROM sessions WHERE session_token = $1 AND expires_at > now() with param: ", token[0..min(token.len-1, 9)], "..."

  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
  
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
        expiresAt: $pg.pqgetvalue(res, 0, 4),
        csrfToken: $pg.pqgetvalue(res, 0, 5)
      )
      echo "[DB DEBUG] Session found: userId=", result.userId, " token=", result.sessionToken[0..10], "..., csrf_token=", result.csrfToken
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
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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
    let res = pg.pqexecParams(dbConn, query.cstring, 3, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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
  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
  
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
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
  except Exception as e:
    echo "[DB ERROR] dbEnableUserMfa failed: ", e.msg
    result = false

proc dbUpdateUserPassword*(userId: int, newHash, newSalt: string): bool =
  # This function now returns bool for success/failure, error messages should be handled by caller
  try:
    ensureDbConnection()

    # 1. Get current user details including password_hash and password_history
    let currentUser = dbGetUserById(userId)
    if currentUser.id == 0:
      echo "[DB ERROR] dbUpdateUserPassword: User not found with ID ", userId
      return false

    var history = currentUser.passwordHistory
    let currentHashedPassword = currentUser.passwordHash

    # 2. Check if newHash is in the current history (before adding the old one)
    # This is a simplified check. A more robust check would be against the hashes *after* adding the current one.
    # However, the requirement is "new password's hash ... must NOT be present in this updated password_history"
    # Let's first construct the "updated password_history" then check.

    # 3. Add current (soon to be old) password_hash to history
    if currentHashedPassword.len > 0 : # Ensure we don't add an empty hash if it's a new user somehow
        history.insert(currentHashedPassword, 0) # Add to the beginning

    # 4. Limit history to 5 entries
    while history.len > 5:
      discard history.pop() # Remove the last (oldest)

    # 5. Check if newHash is in the *updated* history
    for oldHash in history:
      if oldHash == newHash:
        echo "[DB WARN] dbUpdateUserPassword: New password matches one of the last 5 passwords for user ID ", userId
        # This specific error should be communicated back to the route to inform the user.
        # For now, this function just returns false. The route will need to check a specific error type or message if we were to throw.
        return false

    # 6. Convert history sequence to JSON string for DB
    var historyJsonArray = newJArray()
    for h in history:
      historyJsonArray.add(newJString(h))
    let historyJsonString = $historyJsonArray

    # 7. Update user with new hash, new salt, new history, and new password_last_changed
    let query = "UPDATE users SET password_hash = $1, password_salt = $2, password_history = $3::jsonb, password_last_changed = NOW() WHERE id = $4"
    let userIdStr = $userId
    let params: array[4, cstring] = [newHash.cstring, newSalt.cstring, historyJsonString.cstring, userIdStr.cstring]

    echo "[DB DEBUG] Updating password for user ", userId, " with history: ", historyJsonString
    let res = pg.pqexecParams(dbConn, query.cstring, 4, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)

    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
        echo "[DB ERROR] dbUpdateUserPassword DB update failed: ", $pg.pqerrorMessage(dbConn)
        let resultError = $pg.pqresultErrorMessage(res)
        if resultError.len > 0: echo "[DB ERROR] Result error: ", resultError
    else:
        echo "[DB DEBUG] dbUpdateUserPassword successful for user ID ", userId

  except Exception as e:
    echo "[DB ERROR] Exception in dbUpdateUserPassword for user ID ", userId, ": ", e.msg
    result = false

proc dbSetUserVerified*(userId: int): bool =
  try:
    ensureDbConnection()
    let query = "UPDATE users SET is_verified = TRUE WHERE id = $1"
    let userIdStr = $userId
    let params: array[1, cstring] = [userIdStr.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
      echo "[DB ERROR] dbSetUserVerified failed for user ID ", userId, ": ", $pg.pqerrorMessage(dbConn)
  except Exception as e:
    echo "[DB ERROR] Exception in dbSetUserVerified for user ID ", userId, ": ", e.msg
    result = false

proc incrementFailedLogin*(userId: int): bool =
  try:
    ensureDbConnection()
    let query = "UPDATE users SET failed_login_count = failed_login_count + 1, last_failed_login = now() WHERE id = $1"
    let userIdStr = $userId
    let params: array[1, cstring] = [userIdStr.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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
    let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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
  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
  
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
  let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
  
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
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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
    result.add toHex(ord(c), 2) # .toLowerAscii() is often good for consistency
  
  # Set expiration to e.g. 7 days from now
  let expiresAt = $(epochTime().int64 + 604800) # 7 days
  
  # Store in database, csrfToken is initially empty or null by schema default
  discard dbInsertSession(userId, result, expiresAt, "") # Pass empty csrfToken initially

# This proc seems to be defined in ddos_protector.nim's db.nim section now.
# proc dbBlockIp*(ipAddress: string, reason: string, durationMinutes: int): Future[bool]
# Let's ensure there's no duplication or add it here if this is the main db.nim.
# Based on the plan, it should be here.

proc dbBlockIp*(ipAddress: string, reason: string, durationMinutes: int): Future[bool] {.async.} =
  try:
    ensureDbConnection()
    let blockedUntilTime = now() + initDuration(minutes = durationMinutes)
    # PostgreSQL's to_timestamp expects epoch seconds as double.
    let blockedUntilEpochStr = $(blockedUntilTime.toTime().toUnixFloat())

    let query = "INSERT INTO blocked_ips (ip_address, blocked_until, reason) VALUES ($1, to_timestamp($2::double precision), $3) ON CONFLICT (ip_address) DO UPDATE SET blocked_until = EXCLUDED.blocked_until, reason = EXCLUDED.reason"
    let params: array[3, cstring] = [ipAddress.cstring, blockedUntilEpochStr.cstring, reason.cstring]

    echo "[DB DEBUG] Blocking IP: ", ipAddress, " until epoch: ", blockedUntilEpochStr, " for reason: ", reason
    let res = pg.pqexecParams(dbConn, query.cstring, 3, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)

    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
      echo "[DB ERROR] dbBlockIp failed: ", $pg.pqerrorMessage(dbConn)
      let resultError = $pg.pqresultErrorMessage(res)
      if resultError.len > 0: echo "[DB ERROR] Result error: ", resultError
    else:
      echo "[DB INFO] IP ", ipAddress, " blocked successfully until ", $blockedUntilTime
  except Exception as e:
    echo "[DB ERROR] Exception in dbBlockIp: ", e.msg
    result = false
  return result # Explicitly return the future

proc getBlockedStatus*(ipAddress: string): Future[Option[Time]] {.async.} =
  try:
    ensureDbConnection()
    let query = "SELECT blocked_until FROM blocked_ips WHERE ip_address = $1"
    let params: array[1, cstring] = [ipAddress.cstring]

    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)

    if pg.pqresultStatus(res) == pg.PGRES_TUPLES_OK and pg.pqntuples(res) > 0:
      let blockedUntilStr = $pg.pqgetvalue(res, 0, 0)
      # Assuming blocked_until is stored in a format parseable by times.parse
      # E.g., 'YYYY-MM-DD HH:MM:SS' or ISO8601 with timezone.
      # If it's epoch, it needs conversion. PostgreSQL to_timestamp stores TIMESTAMPTZ.
      # Let's try parsing standard timestamp format.
      try:
        let blockedUntilTime = parse(blockedUntilStr, "yyyy-MM-dd HH:mm:sszzz", utc()) # Example format, adjust to actual DB output
        if blockedUntilTime > now():
          return some(blockedUntilTime.toTime())
        else: # Expired ban
          return none(Time)
      except ValueError:
        echo "[DB ERROR] Failed to parse blocked_until timestamp '", blockedUntilStr, "' for IP ", ipAddress
        return none(Time)
    else: # Not found or query error
      if pg.pqresultStatus(res) != pg.PGRES_TUPLES_OK:
         echo "[DB ERROR] getBlockedStatus query failed for IP ", ipAddress, ": ", $pg.pqerrorMessage(dbConn)
      return none(Time)
  except Exception as e:
    echo "[DB ERROR] Exception in getBlockedStatus for IP ", ipAddress, ": ", e.msg
    return none(Time)
  # Nim's async proc implicitly returns a Future wrapping the return type.

proc dbUpdateSessionCsrfToken*(sessionToken: string, newCsrfToken: string): bool =
  try:
    ensureDbConnection()
    let query = "UPDATE sessions SET csrf_token = $1 WHERE session_token = $2"
    let params: array[2, cstring] = [newCsrfToken.cstring, sessionToken.cstring]
    let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
      echo "[DB ERROR] dbUpdateSessionCsrfToken failed: ", $pg.pqerrorMessage(dbConn)
  except Exception as e:
    echo "[DB ERROR] Exception in dbUpdateSessionCsrfToken: ", e.msg
    result = false

proc dbUpdateUserLastLogin*(userId: int): bool =
  try:
    ensureDbConnection()
    # Store current timestamp using PostgreSQL's now() function for consistency
    let query = "UPDATE users SET last_login = now() WHERE id = $1"
    let userIdStr = $userId
    let params: array[1, cstring] = [userIdStr.cstring]
    echo "[DB DEBUG] Updating last login for user ", userId
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    
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
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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
    let res = pg.pqexecParams(dbConn, query.cstring, 3, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)

    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
      echo "[DB ERROR] dbAddBlockedIp failed: ", $pg.pqerrorMessage(dbConn)
      let resultError = $pg.pqresultErrorMessage(res)
      if resultError.len > 0: echo "[DB ERROR] Result error: ", resultError
    echo "[DB DEBUG] dbAddBlockedIp result: ", result

  except Exception as e:
    echo "[DB ERROR] Exception in dbAddBlockedIp: ", e.msg # This dbAddBlockedIp seems to be from a previous version/task.
    result = false

proc dbGetBlockedIp*(ipAddress: string): BlockedIp =
  try:
    ensureDbConnection()
    # Select only if not expired
    let query = "SELECT ip_address, extract(epoch from blocked_until)::text, reason FROM blocked_ips WHERE ip_address = $1 AND blocked_until > now()"
    let params: array[1, cstring] = [ipAddress.cstring]

    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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

    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
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

# Email verification code functions
proc dbCreateVerificationCode*(userId: int, code: string, expiresInHours: int = 24): bool =
  try:
    ensureDbConnection()
    # Insert new verification code
    let query = "INSERT INTO email_verification_codes (user_id, verification_code, expires_at) VALUES ($1, $2, NOW() + INTERVAL '" & $expiresInHours & " hours')"
    let params: array[2, cstring] = [($userId).cstring, code.cstring]
    
    let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)
    
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if not result:
      echo "[DB ERROR] Failed to create verification code for user ", userId, ": ", $pg.pqerrorMessage(dbConn)
  except Exception as e:
    echo "[DB ERROR] Exception in dbCreateVerificationCode: ", e.msg
    result = false

proc dbVerifyEmailCode*(userId: int, code: string): bool =
  try:
    ensureDbConnection()
    # Check if code exists, is valid, not expired, and not used
    let query = "SELECT id FROM email_verification_codes WHERE user_id = $1 AND verification_code = $2 AND expires_at > NOW() AND is_used = FALSE"
    let params: array[2, cstring] = [($userId).cstring, code.cstring]
    
    let res = pg.pqexecParams(dbConn, query.cstring, 2, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)
    
    if pg.pqresultStatus(res) == pg.PGRES_TUPLES_OK and pg.pqntuples(res) > 0:
      # Mark code as used
      let updateQuery = "UPDATE email_verification_codes SET is_used = TRUE WHERE user_id = $1 AND verification_code = $2"
      let updateRes = pg.pqexecParams(dbConn, updateQuery.cstring, 2, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
      defer: pg.pqclear(updateRes)
      
      result = pg.pqresultStatus(updateRes) == pg.PGRES_COMMAND_OK
      if result:
        echo "[DB DEBUG] Email verification code verified and marked as used for user ", userId
      else:
        echo "[DB ERROR] Failed to mark verification code as used: ", $pg.pqerrorMessage(dbConn)
    else:
      echo "[DB DEBUG] Invalid or expired verification code for user ", userId
      result = false
  except Exception as e:
    echo "[DB ERROR] Exception in dbVerifyEmailCode: ", e.msg
    result = false

proc dbCleanupExpiredVerificationCodes*(): bool =
  try:
    ensureDbConnection()
    let query = "DELETE FROM email_verification_codes WHERE expires_at < NOW() OR is_used = TRUE"
    
    let res = pg.pqexec(dbConn, query.cstring)
    defer: pg.pqclear(res)
    
    result = pg.pqresultStatus(res) == pg.PGRES_COMMAND_OK
    if result:
      let rowsAffected = $pg.pqcmdTuples(res)
      echo "[DB DEBUG] Cleaned up ", rowsAffected, " expired/used verification codes"
    else:
      echo "[DB ERROR] Failed to cleanup verification codes: ", $pg.pqerrorMessage(dbConn)
  except Exception as e:
    echo "[DB ERROR] Exception in dbCleanupExpiredVerificationCodes: ", e.msg
    result = false

proc dbGetUserIdByVerificationCode*(code: string): Option[int] =
  try:
    ensureDbConnection()
    let query = "SELECT user_id FROM email_verification_codes WHERE verification_code = $1 AND expires_at > NOW() AND is_used = FALSE"
    let params: array[1, cstring] = [code.cstring]
    
    let res = pg.pqexecParams(dbConn, query.cstring, 1, nil, cast[cstringArray](params[0].unsafeAddr), nil, nil, 0)
    defer: pg.pqclear(res)
    
    if pg.pqresultStatus(res) == pg.PGRES_TUPLES_OK and pg.pqntuples(res) > 0:
      let userIdStr = $pg.pqgetvalue(res, 0, 0)
      try:
        result = some(parseInt(userIdStr))
      except ValueError:
        echo "[DB ERROR] Invalid user_id format in verification code: ", userIdStr
        result = none(int)
    else:
      result = none(int)
  except Exception as e:
    echo "[DB ERROR] Exception in dbGetUserIdByVerificationCode: ", e.msg
    result = none(int)
