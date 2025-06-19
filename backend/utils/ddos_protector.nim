import std/[tables, times, locks, sugar, deques]
# import collections/ringbuffers # Nim's standard library for ring buffers - Not available, using deque instead
import asyncdispatch # For Future type
import ../db/db # For dbBlockIp

const
  REQUEST_LIMIT_PER_WINDOW* = 100
  TIME_WINDOW_SECONDS* = 10
  BAN_DURATION_MINUTES* = 15

var
  ipRequestTimestamps: Table[string, Deque[DateTime]]
  protectorLock: Lock

proc initDdosProtector*() =
  initLock(protectorLock)
  ipRequestTimestamps = initTable[string, Deque[DateTime]]()
  echo "[INFO] DDoS Protector initialized."

proc isRateLimited*(ip: string): Future[bool] {.async.} =
  var banUser = false
  var currentRequestsInWindow = 0

  protectorLock.acquire()
  try:
    if not ipRequestTimestamps.hasKey(ip):
      ipRequestTimestamps[ip] = initDeque[DateTime]()

    var userTimestamps = ipRequestTimestamps[ip]
    userTimestamps.addLast(now())
    
    let windowStart = now() - initDuration(seconds = TIME_WINDOW_SECONDS)

    # Remove old timestamps outside the window
    while userTimestamps.len > 0 and userTimestamps.peekFirst() <= windowStart:
      discard userTimestamps.popFirst()
    
    # Count current requests in window
    currentRequestsInWindow = userTimestamps.len

    # Update the table
    ipRequestTimestamps[ip] = userTimestamps

    echo "[DEBUG] IP: ", ip, " Requests in last ", TIME_WINDOW_SECONDS, "s: ", currentRequestsInWindow, "/", REQUEST_LIMIT_PER_WINDOW

    if currentRequestsInWindow > REQUEST_LIMIT_PER_WINDOW:
      banUser = true
  finally:
    protectorLock.release()

  if banUser:
    echo "[WARN] Rate limit exceeded for IP: ", ip, ". Count: ", currentRequestsInWindow
    # The dbBlockIp proc needs to be available and correctly implemented.
    # It's an async proc, so we need to await it.
    if await dbBlockIp(ip, "Rate limit exceeded in-app (DDOS_PROTECTOR)", BAN_DURATION_MINUTES):
      echo "[INFO] IP ", ip, " banned for ", BAN_DURATION_MINUTES, " minutes due to rate limit."
    else:
      echo "[ERROR] Failed to ban IP ", ip, " via dbBlockIp after rate limit breach."
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
