import std/[asyncdispatch, os]
import utils/email_sender
import utils/env

proc testEmailDirect() {.async.} =
  # Load environment variables
  loadEnvFile()
  
  echo "Testing email sending from main backend context..."
  echo "SMTP_HOST: ", getEnv("SMTP_HOST")
  echo "SMTP_PORT: ", getEnv("SMTP_PORT")
  echo "SMTP_USER: ", getEnv("SMTP_USER")
  echo "SMTP_FROM_NAME: ", getEnv("SMTP_FROM_NAME")
  echo "SMTP_FROM_EMAIL: ", getEnv("SMTP_FROM_EMAIL")
  echo ""
  
  # Test sending a verification email like the main app would
  let verificationCode = "123456"
  let emailSubject = "Your Email Verification Code - ACS Assignment"
  let emailBody = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Verification</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4F46E5; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .code { font-size: 24px; font-weight: bold; background-color: #e5e7eb; padding: 15px; text-align: center; border-radius: 5px; margin: 20px 0; }
        .footer { padding: 10px; text-align: center; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Email Verification</h1>
        </div>
        <div class="content">
            <h2>Hello!</h2>
            <p>Thank you for registering with ACS Assignment. To complete your registration, please use the verification code below:</p>
            <div class="code">""" & verificationCode & """</div>
            <p><strong>Important:</strong></p>
            <ul>
                <li>This code will expire in 24 hours</li>
                <li>Enter this code on the verification page to activate your account</li>
                <li>If you didn't request this registration, please ignore this email</li>
            </ul>
        </div>
        <div class="footer">
            <p>This is an automated email from ACS Assignment. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""
  
  echo "Sending verification email..."
  let result = await sendEmail("00prabinpanta@gmail.com", emailSubject, emailBody, isHtml = true)
  
  if result:
    echo "✓ Verification email sent successfully!"
  else:
    echo "✗ Failed to send verification email"

when isMainModule:
  waitFor testEmailDirect()
