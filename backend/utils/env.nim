import os, strutils

proc loadEnvFile*(filename = ".env") =
  let currentDir = getCurrentDir()
  let filePath = if filename.isAbsolute: filename else: currentDir / filename

  if not fileExists(filePath):
    return
  for line in lines(filePath):
    let clean = line.strip()
    if clean.len == 0 or clean.startsWith("#"): continue
    let parts = clean.split('=', 1)
    if parts.len == 2:
      let key = parts[0].strip()
      let value = parts[1].strip()
      putEnv(key, value)