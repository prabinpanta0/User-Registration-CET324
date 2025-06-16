proc formatSecureCookie*(name, value: string, maxAge: int = 3600): string =
  result = name & "=" & value & "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" & $maxAge

proc formatClearCookie*(name: string): string =
  result = name & "=; Path=/; HttpOnly; Secure; SameSite=Strict; expires=Thu, 01 Jan 1970 00:00:00 GMT"
