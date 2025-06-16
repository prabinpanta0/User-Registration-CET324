import nimcrypto, base64, random, os

proc randomBytes(len: int): seq[byte] =
  result = newSeq[byte](len)
  for i in 0..<len:
    result[i] = byte(rand(256))

proc getAesKey(): seq[byte] =
  # Get AES key from environment, pad or truncate to 32 bytes for AES-256
  let keyStr = getEnv("AES_KEY", "default_fallback_key_32_chars_12")
  result = newSeq[byte](32)
  
  # Convert string to bytes and pad/truncate to 32 bytes
  for i in 0..<32:
    if i < keyStr.len:
      result[i] = byte(keyStr[i])
    else:
      result[i] = 0

proc aesEncrypt*(plaintext: string): (string, string) =
  # Generate random IV for CBC mode
  let ivBytes = randomBytes(16)  # AES block size is 16 bytes
  let key = getAesKey()
  
  # Convert plaintext to bytes and apply PKCS7 padding
  var plaintextBytes = newSeq[byte](plaintext.len)
  for i in 0..<plaintext.len:
    plaintextBytes[i] = byte(plaintext[i])
  
  # PKCS7 padding
  let blockSize = 16
  let padLen = blockSize - (plaintextBytes.len mod blockSize)
  for i in 0..<padLen:
    plaintextBytes.add(byte(padLen))
  
  # Encrypt using AES-256-CBC
  var ctx: CBC[aes256]
  ctx.init(key, ivBytes)  # Both key and ivBytes are seq[byte]
  
  var ciphertext = newSeq[byte](plaintextBytes.len)
  ctx.encrypt(plaintextBytes, ciphertext)  # Both are seq[byte]
  ctx.clear()
  
  result = (encode(ciphertext), encode(ivBytes))

proc aesDecrypt*(b64ciphertext, b64iv: string): string =
  let ivStr = decode(b64iv)
  let ciphertextStr = decode(b64ciphertext)
  let key = getAesKey()
  
  # Convert decoded strings to byte sequences
  var ivBytes = newSeq[byte](ivStr.len)
  for i in 0..<ivStr.len:
    ivBytes[i] = byte(ivStr[i])
  
  var ciphertextBytes = newSeq[byte](ciphertextStr.len)
  for i in 0..<ciphertextStr.len:
    ciphertextBytes[i] = byte(ciphertextStr[i])
  
  # Decrypt using AES-256-CBC
  var ctx: CBC[aes256]
  ctx.init(key, ivBytes)  # Both key and ivBytes are now seq[byte]
  
  var plaintext = newSeq[byte](ciphertextBytes.len)
  ctx.decrypt(ciphertextBytes, plaintext)  # Both are now seq[byte]
  ctx.clear()
  
  # Remove PKCS7 padding
  if plaintext.len > 0:
    let padLen = int(plaintext[^1])
    if padLen > 0 and padLen <= 16 and padLen <= plaintext.len:
      # Verify padding is correct
      var validPadding = true
      for i in (plaintext.len - padLen)..<plaintext.len:
        if plaintext[i] != byte(padLen):
          validPadding = false
          break
      
      if validPadding:
        let unpaddedText = plaintext[0..<(plaintext.len - padLen)]
        result = newString(unpaddedText.len)
        for i in 0..<unpaddedText.len:
          result[i] = char(unpaddedText[i])
      else:
        raise newException(ValueError, "Invalid PKCS7 padding")
    else:
      raise newException(ValueError, "Invalid padding length")
  else:
    result = ""

# Convenience function that takes key as parameter (for backward compatibility)
proc aesEncrypt*(key: string, plaintext: string): (string, string) =
  # Ignore the key parameter and use environment key instead
  result = aesEncrypt(plaintext)

proc aesDecrypt*(key, b64ciphertext, b64iv: string): string =
  # Ignore the key parameter and use environment key instead
  result = aesDecrypt(b64ciphertext, b64iv)
