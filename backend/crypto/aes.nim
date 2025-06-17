import nimcrypto/aes # For aes256 type
import nimcrypto/gcm # For GCM context
import nimcrypto/random # For sysrand.randomBytes
import nimcrypto/utils # For toHex, fromHex
import os, strutils # For getEnv and string operations

# AES-256-GCM constants
const
  AES_KEY_SIZE* = 32 # bytes for AES-256
  GCM_IV_SIZE* = 12  # bytes, 96 bits is recommended for GCM
  GCM_TAG_SIZE* = 16 # bytes, 128 bits for authentication tag

proc generateKey*(): seq[byte] =
  ## Generates a random key of AES_KEY_SIZE bytes.
  result = newSeq[byte](AES_KEY_SIZE)
  randomBytes(result)

proc keyFromHex*(hexKey: string): seq[byte] =
  ## Converts a hex-encoded key string to seq[byte].
  if hexKey.len != AES_KEY_SIZE * 2:
    raise newException(ValueError, "AES key hex string must be " & $(AES_KEY_SIZE * 2) & " characters long.")
  try:
    result = hexKey.fromHex()
  except ValueError:
    raise newException(ValueError, "Invalid hex string for AES key.")

proc aesGcmEncrypt*(key: seq[byte], plaintext: string): (string, string) =
  ## Encrypts plaintext using AES-256-GCM.
  ## Returns (hexEncodedCiphertextAndTag, hexEncodedIv).
  ## Ciphertext includes the authentication tag appended to it.
  if key.len != AES_KEY_SIZE:
    raise newException(ValueError, "AES key must be " & $AES_KEY_SIZE & " bytes long.")

  var iv = newSeq[byte](GCM_IV_SIZE)
  randomBytes(iv)

  var gcmCtx: GCM[aes256]
  gcmCtx.init(key, iv)

  let plaintextBytes = cast[seq[byte]](plaintext)
  var ciphertext = newSeq[byte](plaintextBytes.len)
  var tag = newSeq[byte](GCM_TAG_SIZE)
  
  gcmCtx.encrypt(plaintextBytes, ciphertext)
  gcmCtx.finish(tag) # Get the authentication tag
  gcmCtx.clear()

  # Append tag to ciphertext before hex encoding
  let ciphertextWithTag = ciphertext & tag
  
  return (toHex(ciphertextWithTag), toHex(iv))

proc aesGcmDecrypt*(key: seq[byte], hexCiphertextAndTag: string, hexIv: string): string =
  ## Decrypts hex-encoded ciphertext (with appended tag) using AES-256-GCM and hex-encoded IV.
  ## Returns plaintext string. Raises error on authentication or decryption failure.
  if key.len != AES_KEY_SIZE:
    raise newException(ValueError, "AES key must be " & $AES_KEY_SIZE & " bytes long.")

  var iv: seq[byte]
  try:
    iv = hexIv.fromHex()
  except ValueError:
    raise newException(ValueError, "Invalid IV hex string.")
  
  if iv.len != GCM_IV_SIZE:
    raise newException(ValueError, "IV must be " & $GCM_IV_SIZE & " bytes long.")

  var ciphertextWithTag: seq[byte]
  try:
    ciphertextWithTag = hexCiphertextAndTag.fromHex()
  except ValueError:
    raise newException(ValueError, "Invalid ciphertext hex string.")

  if ciphertextWithTag.len < GCM_TAG_SIZE:
    raise newException(ValueError, "Ciphertext is too short to contain a tag.")

  # Split ciphertext and tag
  let ciphertext = ciphertextWithTag[0 .. ^(GCM_TAG_SIZE+1)]
  let receivedTag = ciphertextWithTag[^GCM_TAG_SIZE .. ^1]

  var gcmCtx: GCM[aes256]
  gcmCtx.init(key, iv)

  var plaintextBytes = newSeq[byte](ciphertext.len)
  gcmCtx.decrypt(ciphertext, plaintextBytes)
  
  var calculatedTag = newSeq[byte](GCM_TAG_SIZE)
  gcmCtx.finish(calculatedTag) # Get the calculated tag
  gcmCtx.clear()

  if calculatedTag != receivedTag:
    # Authentication failed! Do not use plaintext.
    raise newException(ValueError, "AES-GCM authentication failed (tag mismatch).")
  
  result = cast[string](plaintextBytes)

# Example usage or for tests (can be in a separate test file)
when isMainModule:
  echo "AES GCM Tests"
  # Example key (in production, use a securely generated and stored key)
  # let keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" # 64 hex chars = 32 bytes
  # var aesKey = keyFromHex(keyHex)
  var aesKey = generateKey() # Generate a random key for this test run
  echo "Generated AES Key (hex): ", toHex(aesKey)

  let plaintext = "Hello, AES-GCM world! This is a secret message."
  echo "Plaintext: ", plaintext

  try:
    let (encryptedHex, ivHex) = aesGcmEncrypt(aesKey, plaintext)
    echo "Encrypted (hex): ", encryptedHex
    echo "IV (hex): ", ivHex

    let decryptedText = aesGcmDecrypt(aesKey, encryptedHex, ivHex)
    echo "Decrypted: ", decryptedText

    if decryptedText == plaintext:
      echo "AES-GCM Encrypt/Decrypt Successful!"
    else:
      echo "AES-GCM Test Failed: Decrypted text does not match original."

    # Test tampering (should fail decryption/authentication)
    echo "\nTesting tampered ciphertext..."
    let tamperedEncryptedHex = encryptedHex[0 .. ^5] & "0000" # Modify last few bytes
    try:
      let tamperedDecrypted = aesGcmDecrypt(aesKey, tamperedEncryptedHex, ivHex)
      echo "Tampered Decryption Succeeded (UNEXPECTED): ", tamperedDecrypted
    except ValueError as e:
      echo "Tampered Decryption Failed as Expected: ", e.msg

    echo "\nTesting with wrong IV..."
    var wrongIv = ivHex.fromHex()
    wrongIv[0] = wrongIv[0] xor 0xFF # Flip some bits in IV
    let wrongIvHex = toHex(wrongIv)
    try:
      let decryptedWithWrongIv = aesGcmDecrypt(aesKey, encryptedHex, wrongIvHex)
      echo "Decryption with wrong IV Succeeded (UNEXPECTED): ", decryptedWithWrongIv
    except ValueError as e:
      echo "Decryption with wrong IV Failed as Expected: ", e.msg

  except Exception as e:
    echo "Error during AES GCM test: ", e.msg
