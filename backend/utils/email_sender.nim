import std/[asyncdispatch, os, osproc, strutils]

proc sendEmailWithPython(recipient: string, subject: string, body: string, isHtml: bool): Future[bool] {.async.} =
  try:
    let smtpHost = getEnv("SMTP_HOST", "smtp.gmail.com")
    let smtpPort = getEnv("SMTP_PORT", "587")
    let smtpUser = getEnv("SMTP_USER", "")
    let smtpPassword = getEnv("SMTP_PASSWORD", "")
    let fromName = getEnv("SMTP_FROM_NAME", "ACS_ASSIGNMENT")
    let fromEmail = getEnv("SMTP_FROM_EMAIL", "noreply@acs.com")
    
    # Clean the password - remove any comments or extra spaces
    let cleanPassword = smtpPassword.split('#')[0].strip()
    
    let pythonScript = """
import smtplib
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email():
    try:
        smtp_host = sys.argv[1]
        smtp_port = int(sys.argv[2])
        smtp_user = sys.argv[3]
        smtp_password = sys.argv[4]
        from_name = sys.argv[5]
        from_email = sys.argv[6]
        to_email = sys.argv[7]
        subject = sys.argv[8]
        body_file = sys.argv[9]
        content_type = sys.argv[10]
        
        # Read body from file
        with open(body_file, 'r', encoding='utf-8') as f:
            body = f.read()
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # Attach body
        msg.attach(MIMEText(body, content_type))
        
        # Connect to server
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        
        # Send email
        text = msg.as_string()
        server.sendmail(smtp_user, to_email, text)  # Use smtp_user as from address
        server.quit()
        
        print("SUCCESS")
        return True
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        return False

if __name__ == "__main__":
    send_email()
"""
    
    # Write Python script to temporary file
    let scriptPath = "/tmp/send_email.py"
    writeFile(scriptPath, pythonScript)
    
    # Write body to temporary file to avoid shell escaping issues
    let bodyPath = "/tmp/email_body.txt"
    writeFile(bodyPath, body)
    
    # Execute Python script with body file path
    let contentType = if isHtml: "html" else: "plain"
    let escapedSubject = subject.replace("\"", "\\\"")
    
    let cmd = "python3 \"" & scriptPath & "\" " &
              "\"" & smtpHost & "\" " &
              "\"" & smtpPort & "\" " &
              "\"" & smtpUser & "\" " &
              "\"" & cleanPassword & "\" " &
              "\"" & fromName & "\" " &
              "\"" & fromEmail & "\" " &
              "\"" & recipient & "\" " &
              "\"" & escapedSubject & "\" " &
              "\"" & bodyPath & "\" " &
              "\"" & contentType & "\""
    
    echo "[EMAIL] Sending email to: ", recipient
    let (output, exitCode) = execCmdEx(cmd)
    
    # Clean up temporary files
    removeFile(scriptPath)
    removeFile(bodyPath)
    
    if exitCode == 0 and output.contains("SUCCESS"):
      echo "[EMAIL] Email sent successfully via Python to: ", recipient
      return true
    else:
      echo "[EMAIL] Python SMTP failed. Output: ", output
      return false
      
  except Exception as e:
    echo "[EMAIL] Python SMTP error: ", e.msg
    return false

proc sendEmail*(recipient: string, subject: string, body: string, isHtml: bool = false): Future[bool] {.async.} =
  try:
    let smtpUser = getEnv("SMTP_USER", "")
    let smtpPassword = getEnv("SMTP_PASSWORD", "")
    
    if smtpUser == "" or smtpPassword == "":
      echo "[EMAIL] SMTP credentials not configured"
      return false

    # Use Python's smtplib to send email (requires Python3 on system)
    let pythonAvailable = execCmdEx("which python3").exitCode == 0
    if pythonAvailable:
      return await sendEmailWithPython(recipient, subject, body, isHtml)
    else:
      echo "[EMAIL] Python3 not available for SMTP"
      return false
      
  except Exception as e:
    echo "[EMAIL] Error sending email: ", e.msg
    return false

proc getBaseUrl*(): string =
  result = getEnv("BASE_URL", "http://localhost:8080") # Default for dev
  if result[^1] == '/': # Ensure no trailing slash for easy concatenation
    result = result[0 .. ^2]


when isMainModule:
  # Production Email Sender - ACS Assignment
  # This module provides SMTP email functionality for the ACS Assignment application.
  # 
  # Used for:
  # - Email verification during user registration
  # - Password reset emails
  # - MFA recovery code emails
  # - Security notifications
  #
  # Configuration required in .env:
  # - SMTP_HOST: SMTP server hostname (e.g., smtp.gmail.com)
  # - SMTP_PORT: SMTP server port (e.g., 587 for STARTTLS)
  # - SMTP_USER: SMTP username/email address
  # - SMTP_PASSWORD: SMTP password or app-specific password
  # - SMTP_FROM_NAME: Display name for sent emails
  # - SMTP_FROM_EMAIL: Reply-to email address
  #
  # Example usage in application routes:
  # ```nim
  # let emailSent = await sendEmail(
  #   user.email,
  #   "Verify your email address", 
  #   emailVerificationBody
  # )
  # ```
  #
  # For testing SMTP configuration, use: test/test_smtp.nim
  
  echo "ACS Assignment Email Sender Module"
  echo "This is a production email utility."
  echo "For testing, run: nim c -r test/test_smtp.nim"
