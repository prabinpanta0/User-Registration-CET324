type
  User* = object
    id*: int
    username*: string
    email*: string
    passwordHash*: string
    passwordSalt*: string
    mfaEnabled*: bool
    mfaSecretEnc*: string # AES-GCM encrypted
    mfaIv*: string          # IV for mfa_secret_enc
    recoveryCodesEnc*: string # AES-GCM encrypted
    lastLogin*: string
    failedLoginCount*: int
    lockoutUntil*: string
    lastFailedLogin*: string
    passwordHistory*: seq[string]
    passwordLastChanged*: string
    isVerified*: bool

  Session* = object
    id*: int
    userId*: int
    sessionToken*: string
    createdAt*: string
    expiresAt*: string
    csrfToken*: string

  BlockedIp* = object
    ipAddress*: string
    blockedUntil*: string # Store as string, convert to/from timestamp as needed
    reason*: string
