# HTTPS enforcement stub
# WARNING: Jester does not natively enforce HTTPS. Use a reverse proxy (e.g., nginx) with HTTPS in production.
# Optionally, add a runtime check to warn if not using HTTPS.

import jester, os

# hCaptcha configuration
const HCaptchaSiteverifyURL* = "https://hcaptcha.com/siteverify"

proc getSecret*(key: string, default = ""): string =
    result = getEnv(key, default)
    if result == "":
        echo "[CONFIG WARNING] Missing secret for ", key

proc checkHttps*(req: Request) =
    if req.headers.getOrDefault("x-forwarded-proto", @["http"].HttpHeaderValues) != "https":
        echo "[SECURITY WARNING] Connection is not HTTPS!"
