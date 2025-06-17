import std/[tables, times, locks, sugar, json, options]
import collections/ringbuffers
import asyncdispatch
import ../db/db
import ./audit_log # For logging

const
  REQUEST_LIMIT_PER_WINDOW* = 100
  TIME_WINDOW_SECONDS* = 10
  BAN_DURATION_MINUTES* = 15
  # RING_BUFFER_SIZE needs to be large enough to hold all timestamps in a window if they all arrive closely.
  # If TIME_WINDOW_SECONDS is large, this might need adjustment or a different strategy for timestamp storage.
  # For 100 reqs in 10s, this is fine.
  RING_BUFFER_SIZE* = REQUEST_LIMIT_PER_WINDOW + 20 # Margin for buffer operations

var
  ipRequestTimestamps: Table[string, RingBuffer[Time]]
  protectorLock: Lock

proc initDdosProtector*() =
  initLock(protectorLock)
  ipRequestTimestamps = newTable[string, RingBuffer[Time]]()
  echo "[INFO] DDoS Protector initialized."

proc isRateLimited*(ip: string): Future[bool] {.async.} =
  var banUser = false
  var currentRequestsInWindow = 0

  protectorLock.acquire()
  try:
    if not ipRequestTimestamps.hasKey(ip):
      ipRequestTimestamps[ip] = initRingBuffer[Time](RING_BUFFER_SIZE)

    var userTimestamps = ipRequestTimestamps[ip]
    # The ring buffer will automatically discard oldest entries if it's full.
    userTimestamps.add(now())
    # Update the table with the modified ring buffer (if it's a value type, which it is)
    # No, RingBuffer is a ref type, so modification is in place. Re-assignment is not strictly needed
    # unless initRingBuffer was called and it's a new instance.
    # ipRequestTimestamps[ip] = userTimestamps # Not needed if userTimestamps is a reference to the one in table.

    let windowStart = now() - initDuration(seconds = TIME_WINDOW_SECONDS)

    # Iterate over timestamps in the ring buffer to count recent ones
    # A RingBuffer itself doesn't directly support iterating and removing old items efficiently in one go
    # while counting. We need to count items newer than windowStart.
    # A simple approach is to iterate. For very high rates, this could be slow.
    for t in userTimestamps: # Iterates from oldest to newest
      if t > windowStart:
        currentRequestsInWindow += 1

    echo "[DEBUG] IP: ", ip, " Requests in last ", TIME_WINDOW_SECONDS, "s: ", currentRequestsInWindow, "/", REQUEST_LIMIT_PER_WINDOW

    if currentRequestsInWindow > REQUEST_LIMIT_PER_WINDOW:
      banUser = true
  finally:
    protectorLock.release()

  if banUser:
    echo "[WARN] Rate limit exceeded for IP: ", ip, ". Count: ", currentRequestsInWindow
    let reason = "Rate limit exceeded in-app (DDOS_PROTECTOR)"
    if await dbBlockIp(ip, reason, BAN_DURATION_MINUTES):
      echo "[INFO] IP ", ip, " banned for ", BAN_DURATION_MINUTES, " minutes due to rate limit."
      # Log audit event for IP block due to rate limit
      discard logAuditEvent(
        eventType = "IP_BLOCKED_RATE_LIMIT",
        clientIpOverride = some(ip),
        additionalData = %*{"reason": reason, "duration_minutes": BAN_DURATION_MINUTES, "triggering_count": currentRequestsInWindow}
      )
    else:
      echo "[ERROR] Failed to ban IP ", ip, " via dbBlockIp after rate limit breach."
      # Log failure to ban
      discard logAuditEvent(
        eventType = "IP_BLOCK_FAILED_RATE_LIMIT",
        clientIpOverride = some(ip),
        additionalData = %*{"reason": reason, "error": "dbBlockIp returned false"}
      )
    return true

  return false

when isMainModule:
  # Example Usage - requires async context for isRateLimited
  proc main() {.async.} =
    initDdosProtector()
    let testIp = "127.0.0.1"
    echo "Testing rate limiter for IP: ", testIp

    for i in 1..(REQUEST_LIMIT_PER_WINDOW + 5):
      echo "Request #", i
      if await isRateLimited(testIp):
        echo "IP ", testIp, " is now rate limited (and should be banned)."
        # Check DB manually to see if 127.0.0.1 is in blocked_ips
        break
      sleep(50) # Simulate some delay between requests, reduce for faster testing

    # Simulate time passing to see if ban expires or rate limit window clears
    # This part is harder to test directly without a real DB and time progression.
    echo "Test finished."

  waitFor main()
