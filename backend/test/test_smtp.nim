import std/[asyncdispatch, os]
import ../utils/email_sender
import ../utils/env

proc testSmtp() {.async.} =
  # Load environment variables
  loadEnvFile()
  
  echo "Testing SMTP email sending..."
  echo "SMTP_HOST: ", getEnv("SMTP_HOST")
  echo "SMTP_PORT: ", getEnv("SMTP_PORT")
  echo "SMTP_USER: ", getEnv("SMTP_USER")
  echo "SMTP_FROM_NAME: ", getEnv("SMTP_FROM_NAME")
  echo "SMTP_FROM_EMAIL: ", getEnv("SMTP_FROM_EMAIL")
  echo ""
  
  # Test sending a plain text email
  echo "Sending plain text test email..."
  let textResult = await sendEmail(
    "00prabinpanta@gmail.com",
    "Test Email from ACS Assignment - Plain Text",
    "Hello!\n\nThis is a test email sent from the ACS Assignment application.\n\nIf you receive this, the SMTP configuration is working correctly.\n\nBest regards,\nACS Assignment Team"
  )
  
  if textResult:
    echo "✓ Plain text email sent successfully!"
  else:
    echo "✗ Failed to send plain text email"
  
  echo ""
  
  # Test sending an HTML email
  echo "Sending HTML test email..."
  let htmlBody = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Test Email</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4F46E5; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .footer { padding: 10px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ACS Assignment - Test Email</h1>
        </div>
        <div class="content">
            <h2>Hello!</h2>
            <p>This is a <strong>test HTML email</strong> sent from the ACS Assignment application.</p>
            <p>If you receive this email with proper formatting, the SMTP configuration is working correctly.</p>
            <ul>
                <li>✓ SMTP connection established</li>
                <li>✓ Authentication successful</li>
                <li>✓ Email delivery working</li>
                <li>✓ HTML formatting supported</li>
            </ul>
            <p>Thank you for testing!</p>
        </div>
        <div class="footer">
            <p>This is an automated test email from ACS Assignment</p>
        </div>
    </div>
</body>
</html>
"""
  
  let htmlResult = await sendEmail(
    "00prabinpanta@gmail.com",
    "Test Email from ACS Assignment - HTML",
    htmlBody,
    isHtml = true
  )
  
  if htmlResult:
    echo "✓ HTML email sent successfully!"
  else:
    echo "✗ Failed to send HTML email"
  
  echo ""
  echo "SMTP test completed!"

when isMainModule:
  waitFor testSmtp()
