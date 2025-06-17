import jester, strutils, options, json
import ../db/db # For dbGetSessionByToken
import ../db/models # For Session model
import ./audit_log # For logging CSRF failures

# Note: The `setCookie` used here is Jester's `setCookie(Response, Cookie)`
# For deleting, we'd typically pass a cookie with expiry in the past.
# Jester's `setCookie` might need to be called from a context where `Response` is available.
# This utility proc will return a bool, and the route handler will manage the response/cookie deletion.

proc verifyCsrf*(request: Request, isPreSession: bool = false): bool =
  var submittedToken: string

  # Try to get token from form body (common for standard HTML forms)
  submittedToken = request.bodyParams.getOrDefault("csrf_token", "")

  # If not in form body, try headers (common for AJAX)
  if submittedToken.len == 0:
    submittedToken = request.headers.getOrDefault("X-CSRF-Token", "")

  # If still not found, try query params (less common for CSRF, but possible)
  if submittedToken.len == 0:
    submittedToken = request.params.getOrDefault("csrf_token", "")

  if submittedToken.len == 0:
    echo "[CSRF FAIL] Submitted CSRF token is missing."
    # Log this failure. User ID might not be available.
    discard logAuditEvent("CSRF_VALIDATION_FAILURE_TOKEN_MISSING", request)
    return false

  if isPreSession:
    let cookieToken = request.cookies.getOrDefault("csrf_token_value", "")
    if cookieToken.len == 0:
      echo "[CSRF FAIL] CSRF cookie (csrf_token_value) is missing for pre-session check."
      discard logAuditEvent("CSRF_VALIDATION_FAILURE_PRE_SESSION_COOKIE_MISSING", request)
      return false

    if submittedToken == cookieToken:
      echo "[CSRF OK] Pre-session CSRF token matches cookie."
      return true
    else:
      echo "[CSRF FAIL] Pre-session CSRF token mismatch. Submitted: '", submittedToken, "', Cookie: '", cookieToken, "'"
      discard logAuditEvent("CSRF_VALIDATION_FAILURE_PRE_SESSION_MISMATCH", request,
        additionalData = %*{"submitted_token": submittedToken, "cookie_token": cookieToken})
      return false
  else:
    let sessionTokenCookie = request.cookies.getOrDefault("session", "")
    if sessionTokenCookie.len == 0:
      echo "[CSRF FAIL] Main session cookie is missing for authenticated CSRF check."
      discard logAuditEvent("CSRF_VALIDATION_FAILURE_SESSION_COOKIE_MISSING", request)
      return false

    ensureDbConnection()
    let userSession = dbGetSessionByToken(sessionTokenCookie)
    var userIdForLog: Option[int] = none()
    if userSession.id != 0: userIdForLog = some(userSession.userId)

    if userSession.id == 0 or userSession.csrfToken.len == 0:
      echo "[CSRF FAIL] No valid session or CSRF token not found in session. Session ID: ", userSession.id
      discard logAuditEvent("CSRF_VALIDATION_FAILURE_NO_SESSION_OR_TOKEN_IN_SESSION", request, userId = userIdForLog)
      return false

    if submittedToken == userSession.csrfToken:
      echo "[CSRF OK] Session CSRF token matches for user ID: ", userSession.userId
      return true
    else:
      echo "[CSRF FAIL] Session CSRF token mismatch for user ID: ", userSession.userId, ". Submitted: '", submittedToken, "', Session stores: '", userSession.csrfToken, "'"
      discard logAuditEvent("CSRF_VALIDATION_FAILURE_SESSION_MISMATCH", request, userId = userIdForLog,
        additionalData = %*{"submitted_token": submittedToken, "expected_token_snippet": userSession.csrfToken[0 .. min(userSession.csrfToken.len-1, 5)] & "..."})
      return false

# Helper to be called by routes after successful pre-session CSRF verification
proc clearCsrfDoubleSubmitCookie*(response: Response) =
  # To "delete" a cookie, set its expiry to a past date.
  # Jester's setCookie will handle creating the correct Set-Cookie header.
  var cookieToClear = newCookie("csrf_token_value", "", expires = past()) # `past()` from `times`
  cookieToClear.path = "/"
  # Ensure other attributes match how it was set if necessary (Secure, SameSite)
  # cookieToClear.secure = true # If it was set with Secure
  cookieToClear.sameSite = SameSite.Strict
  setCookie(response, cookieToClear) # This requires `response` object from Jester route
  echo "[CSRF] Cleared csrf_token_value cookie."

# Note: Direct usage of `setCookie(response, ...)` from this util might be tricky
# if `response` object isn't easily passed around.
# An alternative is for `verifyCsrf` to return an enum/object indicating success
# and if cookie should be cleared, then route handler does it.
# For now, the route handler will call `clearCsrfDoubleSubmitCookie` explicitly.

when isMainModule:
  # Basic tests (conceptual, cannot fully test without Request object)
  echo "CSRF Validator tests (conceptual):"

  # Test case 1: Pre-session, match
  # Mock request: bodyParams["csrf_token"] = "abc", cookies["csrf_token_value"] = "abc"
  echo "Test 1 (Pre-session Match): Expected true"
  # Simulating: if "abc" == "abc": echo "Pass" else: echo "Fail"

  # Test case 2: Pre-session, mismatch
  # Mock request: bodyParams["csrf_token"] = "xyz", cookies["csrf_token_value"] = "abc"
  echo "Test 2 (Pre-session Mismatch): Expected false"
  # Simulating: if "xyz" == "abc": echo "Fail" else: echo "Pass (mismatch is expected outcome)"

  # Test case 3: Post-session, match
  # Mock request: headers["X-CSRF-Token"] = "123", session.csrfToken = "123"
  echo "Test 3 (Post-session Match): Expected true"

  # Test case 4: Post-session, mismatch
  # Mock request: bodyParams["csrf_token"] = "789", session.csrfToken = "123"
  echo "Test 4 (Post-session Mismatch): Expected false"

  # Test case 5: Token missing
  echo "Test 5 (Token Missing): Expected false"

  echo "CSRF Validator conceptual tests complete."
