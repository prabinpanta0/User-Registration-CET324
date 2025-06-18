import std/[times, asyncdispatch, options, os]
import ./env # For BASE_URL, potentially sender email

# Configuration - consider moving to env.nim or a config module
const SENDER_EMAIL = "noreply@example.com" # Replace with your domain or get from env

proc sendEmail*(recipient: string, subject: string, body: string, isHtml: bool = false): Future[bool] {.async.} =
  # Temporary implementation that logs instead of sending actual emails
  # This is to avoid SMTP SSL compilation issues
  echo "[EMAIL] Would send email to: ", recipient
  echo "[EMAIL] Subject: ", subject
  echo "[EMAIL] Content (HTML=", isHtml, "): ", body[0..min(100, body.len-1)], if body.len > 100: "..." else: ""
  return true # Always return success for development

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
