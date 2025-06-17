import jester, strutils

proc getClientIp*(request: Request): string =
  # Order of preference: X-Forwarded-For (if multiple, take first), X-Real-IP, remoteAddress.
  # Assumes Nginx or other reverse proxy is correctly setting these headers.
  var ip = request.headers.getOrDefault("X-Forwarded-For", "")
  if ip.len > 0:
    # X-Forwarded-For can contain a comma-separated list if there are multiple proxies.
    # The first IP in the list is generally the original client IP.
    let parts = ip.split(',')
    if parts.len > 0:
      let firstIp = parts[0].strip()
      if firstIp.len > 0: return firstIp

  ip = request.headers.getOrDefault("X-Real-IP", "")
  if ip.len > 0:
    return ip

  # Fallback to Jester's remoteAddress.
  # In a typical proxy setup, this might be the proxy's IP address.
  return request.remoteAddress

when isMainModule:
  # This module is not meant to be run directly in production,
  # but you could add test cases here for the getClientIp proc
  # by mocking Jester Request objects if a testing framework allows.
  echo "network.nim compiled (intended for import)"
  # Example (conceptual - cannot run without a Request object):
  # block:
  #   var mockRequest: Request
  #   # How to mock headers and remoteAddress depends on Jester's internals or a test framework
  #   echo getClientIp(mockRequest)
