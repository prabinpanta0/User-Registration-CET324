import std/[asyncdispatch, httpclient, sha1, strutils, times]
import os

proc isPasswordPwned*(password: string): Future[bool] {.async.} =
  # Calculate SHA-1 hash of the password
  let hash = ($sha1.secureHash(password)).toUpper()
  let prefix = hash[0..4]
  let suffix = hash[5..^1]

  # Prepare the API request
  let url = "https://api.pwnedpasswords.com/range/" & prefix
  var client = newAsyncHttpClient()
  client.headers = newHttpHeaders({"User-Agent": "NimHIBPChecker/1.0"})
  # Set a more aggressive timeout for faster responses
  client.timeout = 2000 # 2 seconds in milliseconds

  try:
    echo "Checking HIBP for prefix: ", prefix
    let response = await client.get(url)

    if response.code == Http200:
      let responseBody = await response.body()
      let lines = responseBody.splitLines()
      for line in lines:
        let parts = line.split(':')
        if parts.len == 2 and parts[0] == suffix:
          echo "Password found in HIBP database (prefix: ", prefix, ")"
          return true
      echo "Password not found in HIBP response for prefix: ", prefix
      return false
    else:
      echo "Error from HIBP API: HTTP ", response.code, " for prefix ", prefix
      # Default to not pwned to avoid blocking users
      return false
  except CatchableError as e:
    echo "Exception during HIBP check for prefix ", prefix, ": ", e.msg
    # Default to not pwned in case of network errors or timeouts
    return false
  finally:
    client.close()

when isMainModule:
  # Example Usage (for testing purposes)
  echo "Running HIBP check example..."
  let testPasswords = @["password123", "P@$$wOrd", "thisIsAStrongPassword123!"]
  for pw in testPasswords:
    let pwned = waitFor isPasswordPwned(pw)
    echo "Password '", pw, "' pwned status: ", pwned

  # Test with a known pwned password (e.g. "password")
  let knownPwned = "password"
  let pwnedStatus = waitFor isPasswordPwned(knownPwned)
  echo "Password '", knownPwned, "' pwned status: ", pwnedStatus

  # Test with a likely not pwned password
  let likelyNotPwned = "SuperSecurePassword123!@#" & $getTime().toUnix()
  let notPwnedStatus = waitFor isPasswordPwned(likelyNotPwned)
  echo "Password '", likelyNotPwned, "' pwned status: ", notPwnedStatus
