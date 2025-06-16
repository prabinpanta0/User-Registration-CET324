import times, tables, sequtils, strutils
import ../db/db # For dbGetBlockedIp, dbAddBlockedIp

# Configuration for rate limiting specific routes/actions
type
  RateLimitConfig* = object
    routeIdentifier*: string       # e.g., "login_attempt", "register_attempt", "mfa_verify"
    maxAttemptsShortTerm*: int    # Max attempts in the short-term window before triggering long-term block
    windowSecShortTerm*: int      # Duration of the short-term in-memory window (seconds)
    blockDurationSecLongTerm*: int64 # Duration for the database-backed block (seconds)

# In-memory store for short-term rate limiting
# Key: (IP Address, Route Identifier), Value: Sequence of attempt timestamps (epoch seconds)
var rateLimitStore: Table[(string, string), seq[int64]]

proc isRequestAllowed*(ip: string, config: RateLimitConfig): bool =
  # 1. Check if IP is already blocked in the database (long-term block)
  let currentBlock = dbGetBlockedIp(ip)
  if currentBlock.ipAddress.len > 0:
    try:
      let blockedUntilEpoch = parseBiggestInt(currentBlock.blockedUntil)
      if blockedUntilEpoch > epochTime().int64:
        echo "[RATE LIMIT] IP ", ip, " DENIED for ", config.routeIdentifier, ". DB Blocked until epoch: ", blockedUntilEpoch
        return false # IP is currently DB-blocked
    except ValueError:
      # Handle cases where blockedUntil string might not be a valid number (should not happen ideally)
      echo "[RATE LIMIT ERROR] Could not parse blockedUntil value '", currentBlock.blockedUntil, "' for IP ", ip
      # Potentially treat as blocked or allow with caution, for now, let short-term check proceed.

  # 2. Perform short-term in-memory rate limiting
  let now = epochTime().int64
  let key = (ip, config.routeIdentifier)

  if key notin rateLimitStore:
    rateLimitStore[key] = @[]

  # Remove attempts older than the current short-term window
  rateLimitStore[key] = rateLimitStore[key].filterIt(now - it < config.windowSecShortTerm.int64)

  # Check if the number of recent attempts exceeds the short-term threshold
  if rateLimitStore[key].len >= config.maxAttemptsShortTerm:
    echo "[RATE LIMIT] IP ", ip, " short-term limit EXCEEDED for ", config.routeIdentifier, ". Attempts: ", rateLimitStore[key].len
    # Threshold met, trigger long-term DB block
    let blockUntilTs = now + config.blockDurationSecLongTerm
    let reason = "Rate limit exceeded for " & config.routeIdentifier & " after " & $rateLimitStore[key].len & " attempts in " & $config.windowSecShortTerm & "s."

    echo "[RATE LIMIT] Attempting to DB block IP ", ip, " until epoch ", blockUntilTs, " for reason: ", reason
    if not dbAddBlockedIp(ip, $blockUntilTs, reason):
      # Log if DB block failed, but still deny the request based on in-memory limit
      echo "[RATE LIMIT ERROR] Failed to add IP ", ip, " to DB block list for ", config.routeIdentifier

    return false # Deny request due to exceeding short-term limit (and now DB blocked)

  # Record current attempt
  rateLimitStore[key].add(now)
  echo "[RATE LIMIT] IP ", ip, " ALLOWED for ", config.routeIdentifier, ". Attempts: ", rateLimitStore[key].len, "/", config.maxAttemptsShortTerm
  return true # Request allowed
 