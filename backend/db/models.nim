type
  User* = object
    id*: int
    username*: string
    email*: string
    passwordHash*: string
    passwordSalt*: string
    mfaEnabled*: bool
    mfaSecretEnc*: string # AES-GCM encrypted
    recoveryCodesEnc*: string # AES-GCM encrypted
    lastLogin*: string
    failedLoginCount*: int
    lockoutUntil*: string
    lastFailedLogin*: string

  Session* = object
    id*: int
    userId*: int
    sessionToken*: string
    createdAt*: string
    expiresAt*: string
