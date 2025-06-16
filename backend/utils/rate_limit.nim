import times, tables, sequtils

var rateLimitStore: Table[(string, string), seq[int64]]

proc checkRateLimit*(ip, route: string, maxAttempts: int = 5, windowSec: int = 60): bool =
  let now = epochTime().int64
  let key = (ip, route)
  if key notin rateLimitStore:
    rateLimitStore[key] = @[]
  # Remove old attempts
  rateLimitStore[key] = rateLimitStore[key].filterIt(now - it < windowSec.int64)
  if rateLimitStore[key].len >= maxAttempts:
    return false
  rateLimitStore[key].add(now)
  return true
 