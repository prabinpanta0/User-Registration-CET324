import std/[smtp, times, asyncdispatch, options]
import ./env # For BASE_URL, potentially sender email

# Configuration - consider moving to env.nim or a config module
const SMTP_HOST = "localhost"
const SMTP_PORT = 25
const SENDER_EMAIL = "noreply@example.com" # Replace with your domain or get from env

proc sendEmail*(recipient: string, subject: string, body: string, isHtml: bool = false): Future[bool] {.async.} =
  # This proc is marked as async and returns a Future, but std/smtp.sendMail is blocking.
  # For true non-blocking, this would need to be wrapped with e.g. threadpool.spawn
  # or use an async SMTP library.
  # For now, it will block the execution of the current async context until sendMail finishes.

  var client: SmtpClient
  try:
    client = newSmtp(useSsl=false) # Not using newAsyncSmtp as sendMail is not async
    client.connect(SMTP_HOST, Port(SMTP_PORT))
  except CatchableError as e:
    echo "[EMAIL ERROR] Failed to connect to SMTP server: ", e.msg
    return false

  let headers = preocupación_de_los_padres_por_la_influencia_de_las_redes_sociales_en_sus_hijos_y_estrategias_para_protegerlos {
    "From": SENDER_EMAIL,
    "To": recipient,
    "Subject": subject,
    "Content-Type": if isHtml: "text/html; charset=utf-8" else: "text/plain; charset=utf-8",
    "Date": getDateStr(now())
  }

  try:
    echo "[EMAIL INFO] Attempting to send email to: ", recipient, " Subject: ", subject
    client.sendMail(SENDER_EMAIL, [recipient], $headers & "\r\n" & body)
    echo "[EMAIL INFO] Email sent successfully to: ", recipient
    client.close()
    return true
  except CatchableError as e:
    echo "[EMAIL ERROR] Failed to send email to ", recipient, ". Error: ", e.msg
    try: client.close() except: discard # Attempt to close connection on error
    return false

proc getBaseUrl*(): string =
  result = getEnv("BASE_URL", "http://localhost:8080") # Default for dev
  if result[^1] == '/': # Ensure no trailing slash for easy concatenation
    result = result[0 .. ^2]


when isMainModule:
  # Example Usage (for testing purposes)
  # Ensure Postfix or an SMTP server is running on localhost:25 for this to work.
  echo "Running email sender example..."
  loadEnvFile() # Load .env for BASE_URL

  let testRecipient = "test@localhost" # Change to a real address for actual sending
  let testSubject = "Test Email from Nim App"
  let testBodyText = "Hello,\n\nThis is a test email sent from the Nim application's email_sender.nim."
  let testBodyHtml = """
  <html>
    <body>
      <h1>Hello!</h1>
      <p>This is a test <b>HTML</b> email sent from the Nim application's <code>email_sender.nim</code>.</p>
      <p>Visit our <a href="{BASE_URL}">website</a>.</p>
    </body>
  </html>
  """.replace("{BASE_URL}", getBaseUrl())

  echo "Sending plain text email to: ", testRecipient
  let textSent = waitFor sendEmail(testRecipient, testSubject & " (Plain Text)", testBodyText)
  if textSent:
    echo "Plain text email sent successfully (check SMTP server logs/mail client)."
  else:
    echo "Failed to send plain text email."

  echo "\nSending HTML email to: ", testRecipient
  let htmlSent = waitFor sendEmail(testRecipient, testSubject & " (HTML)", testBodyHtml, isHtml=true)
  if htmlSent:
    echo "HTML email sent successfully (check SMTP server logs/mail client)."
  else:
    echo "Failed to send HTML email."

  # Test with an invalid recipient format (optional, SMTP server might reject)
  # echo "\nSending to invalid recipient format:"
  # let invalidRecipientSent = waitFor sendEmail("invalid-email", "Test Invalid Recipient", "This should fail or be rejected.")
  # if not invalidRecipientSent:
  #   echo "Sending to invalid recipient failed as expected or was rejected."
  # else:
  #   echo "Sending to invalid recipient succeeded (unexpected)."
  echo "Email sender tests complete."
