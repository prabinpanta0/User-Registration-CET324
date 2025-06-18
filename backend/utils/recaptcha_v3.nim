import asyncdispatch, httpclient, json, strutils
import ./env # For getRecaptchaV3SecretKey and getRecaptchaV3ScoreThreshold

const RecaptchaV3VerifyURL = "https://www.google.com/recaptcha/api/siteverify"

proc verifyRecaptchaV3*(token: string, clientIp: string = ""): Future[bool] {.async.} =
  let secretKey = getRecaptchaV3SecretKey()
  if secretKey.len == 0:
    echo "[ERROR] reCAPTCHA v3 secret key is not configured. Verification skipped and failed."
    return false

  let scoreThreshold = getRecaptchaV3ScoreThreshold()

  try:
    let client = newAsyncHttpClient()
    defer: client.close()

    # Prepare POST data
    var postData = "secret=" & secretKey & "&response=" & token
    if clientIp.len > 0:
      postData.add("&remoteip=" & clientIp)

    echo "[DEBUG] Verifying reCAPTCHA v3 token for IP: ", clientIp

    let response = await client.request(RecaptchaV3VerifyURL, httpMethod = HttpPost, 
                                       body = postData, 
                                       headers = newHttpHeaders({"Content-Type": "application/x-www-form-urlencoded"}))

    if response.code != Http200:
      echo "[ERROR] reCAPTCHA v3 request failed with status: ", response.code
      return false

    let responseBody = await response.body
    echo "[DEBUG] reCAPTCHA v3 response body: ", responseBody
    let jsonResponse = parseJson(responseBody)

    if not jsonResponse.hasKey("success") or not jsonResponse["success"].getBool(false):
      let errorCodes = if jsonResponse.hasKey("error-codes"): $jsonResponse["error-codes"] else: "N/A"
      echo "[INFO] reCAPTCHA v3 verification failed. Error codes: ", errorCodes
      return false

    # Check score
    if jsonResponse.hasKey("score"):
      let score = jsonResponse["score"].getFloat(0.0)
      echo "[DEBUG] reCAPTCHA v3 score: ", score, " (threshold: ", scoreThreshold, ")"
      
      if score >= scoreThreshold:
        echo "[INFO] reCAPTCHA v3 verification successful with score: ", score
        return true
      else:
        echo "[INFO] reCAPTCHA v3 verification failed. Score too low: ", score
        return false
    else:
      echo "[WARN] reCAPTCHA v3 response missing score field"
      return false

  except Exception as e:
    echo "[ERROR] Exception during reCAPTCHA v3 verification: ", e.msg
    return false
