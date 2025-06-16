import jester
import ../utils/csrf

routes:
  get "/csrf-token":
    let ip = request.remoteAddr
    let token = generateCsrfToken(ip)
    resp Http200, token 