import ../crypto/aes
import os, times

const AUDIT_LOG_FILE = "audit.log"

proc logAudit*(event, ip, user: string) =
  let timestamp = $now()
  let msg = event & "," & ip & "," & user & "," & timestamp
  let (enc, iv) = aesEncrypt(msg)  # Uses environment AES_KEY automatically
  let line = enc & ":" & iv & "\n"
  
  # Safely append to file
  try:
    let existingContent = if fileExists(AUDIT_LOG_FILE): readFile(AUDIT_LOG_FILE) else: ""
    writeFile(AUDIT_LOG_FILE, existingContent & line)
  except IOError:
    # If we can't write to audit log, at least don't crash the application
    discard 