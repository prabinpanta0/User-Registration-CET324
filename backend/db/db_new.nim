import tables, os, strutils
import postgres as pg
import models

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
  if dbUrl.len == 0:
    raise newException(ValueError, "DB_URL environment variable is not set.")
  try:
    dbConn = pg.pqconnectdb(cstring(dbUrl))
  except Exception as e:
    raise newException(OSError, "Failed to connect to the database: " & e.msg)

proc dbInsertUser*(username, email, hash, salt: string): bool =
  try:
    # Note: This is simplified - in production you'd use parameterized queries
    let query = "INSERT INTO users (username, email, password_hash, password_salt) VALUES ('" & 
                username & "', '" & email & "', '" & hash & "', '" & salt & "')"
    result = execQuery(query)
  except:
    result = false

proc dbGetUserByUsernameOrEmail*(userOrEmail: string): User =
  let query = "SELECT id, username, email, password_hash, password_salt, mfa_enabled, mfa_secret_enc, recovery_codes_enc, last_login FROM users WHERE username = '" & userOrEmail & "' OR email = '" & userOrEmail & "'"
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
    let query = "INSERT INTO sessions (user_id, session_token, created_at, expires_at) VALUES (" & 
                $userId & ", '" & token & "', now(), '" & expiresAt & "')"
    result = execQuery(query)
  except:
    result = false

proc dbGetSessionByToken*(token: string): Session =
  let query = "SELECT id, user_id, session_token, created_at, expires_at FROM sessions WHERE session_token = '" & token & "' AND expires_at > now()"
  let res = execQueryWithResult(query)
  
  try:
    let status = pg.pqresultStatus(res)
    if status != pg.PGRES_TUPLES_OK:
      return Session()
    
    let nrows = pg.pqntuples(res)
    if nrows > 0:
      result = Session(
        id: parseInt($pg.pqgetvalue(res, 0, 0)),
        userId: parseInt($pg.pqgetvalue(res, 0, 1)),
        sessionToken: $pg.pqgetvalue(res, 0, 2),
        createdAt: $pg.pqgetvalue(res, 0, 3),
        expiresAt: $pg.pqgetvalue(res, 0, 4)
      )
    else:
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
