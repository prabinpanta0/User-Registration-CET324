import jester, strutils, options, times
import ../db/db # For dbGetSessionByToken
import ../db/models # For Session model

# Note: The `setCookie` used here is Jester's `setCookie(Response, Cookie)`
# For deleting, we'd typically pass a cookie with expiry in the past.
# Jester's `setCookie` might need to be called from a context where `Response` is available.
# This utility proc will return a bool, and the route handler will manage the response/cookie deletion.

proc verifyCsrf*(request: Request, isPreSession: bool = false): bool =
  var submittedToken: string

  # Try to get token from form parameters (common for standard HTML forms)
  # In Jester, form data is typically accessed through request.params
  submittedToken = request.params.getOrDefault("csrf_token", "")

  # If not in form body, try headers (common for AJAX)
  if submittedToken.len == 0:
    try:
      submittedToken = request.headers["X-CSRF-Token"]
    except KeyError:
      submittedToken = ""

  # If still not found, try query params (less common for CSRF, but possible)
  if submittedToken.len == 0:
    submittedToken = request.params.getOrDefault("csrf_token", "")

  if submittedToken.len == 0:
    echo "[CSRF FAIL] Submitted CSRF token is missing."
    return false

  if isPreSession:
    # Double Submit Cookie: Compare with csrf_token_value cookie
    let cookieToken = request.cookies.getOrDefault("csrf_token_value", "")
    if cookieToken.len == 0:
      echo "[CSRF FAIL] CSRF cookie (csrf_token_value) is missing for pre-session check."
      return false

    if submittedToken == cookieToken:
      echo "[CSRF OK] Pre-session CSRF token matches cookie."
      # The calling route should handle deleting/expiring the csrf_token_value cookie.
      return true
    else:
      echo "[CSRF FAIL] Pre-session CSRF token mismatch. Submitted: '", submittedToken, "', Cookie: '", cookieToken, "'"
      return false
  else:
    # Synchronizer Token Pattern: Compare with token in session (DB)
    let sessionTokenCookie = request.cookies.getOrDefault("session", "")
    if sessionTokenCookie.len == 0:
      echo "[CSRF FAIL] Main session cookie is missing for authenticated CSRF check."
      return false

    ensureDbConnection() # Ensure DB connection before query
    let userSession = dbGetSessionByToken(sessionTokenCookie)
    if userSession.id == 0 or userSession.csrfToken.len == 0: # No valid session or no CSRF token in session
      echo "[CSRF FAIL] No valid session or CSRF token not found in session. Session ID: ", userSession.id
      return false

    if submittedToken == userSession.csrfToken:
      echo "[CSRF OK] Session CSRF token matches for user ID: ", userSession.userId
      return true
    else:
      echo "[CSRF FAIL] Session CSRF token mismatch for user ID: ", userSession.userId, ". Submitted: '", submittedToken, "', Session stores: '", userSession.csrfToken, "'"
      return false

# Helper to be called by routes after successful pre-session CSRF verification  
proc getClearCsrfCookie*(): tuple[name: string, value: string, expires: string, path: string] =
  # Returns cookie parameters that can be used by the route to clear the CSRF cookie
  result = (
    name: "csrf_token_value", 
    value: "", 
    expires: $(now() - 1.days), 
    path: "/"
  )
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
