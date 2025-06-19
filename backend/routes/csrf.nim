import jester, json, times
import ../crypto/aes

routes:
  get "/csrf-token":
    # Generate a secure random token for double-submit cookie pattern
    let token = generateSecureToken(32)
    
    # Set the token as a secure cookie
    var csrfCookie = newCookie("csrf_token_value", token)
    csrfCookie.path = "/"
    csrfCookie.expires = future(30.minutes)
    csrfCookie.sameSite = SameSite.Lax
    # csrfCookie.secure = true  # Enable in production with HTTPS
    setCookie(csrfCookie)
    
    # Return JSON response with the token
    resp Http200, %*{"csrf_token": token} 