import random, strutils, tables
var csrfStore: Table[string, string]

proc generateCsrfToken(ip: string): string =
  let token = rand(1000000..9999999).intToStr & rand(1000000..9999999).intToStr
  csrfStore[ip] = token
  token

proc checkCsrf(token: string): bool =
  for k, v in csrfStore.pairs:
    if v == token:
      return true
  return false
