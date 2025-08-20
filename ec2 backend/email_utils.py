import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_verification_email(to_email: str, code: str) -> None:
    """Send a simple plaintext email with the verification code.

    Environment variables expected:
      - EMAIL_ADDRESS (Gmail address)
      - EMAIL_PASS (Gmail App Password)
    """
    # Support both generic SMTP_* and simple Gmail-style EMAIL_ADDRESS/EMAIL_PASS
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USERNAME") or os.getenv("EMAIL_ADDRESS")
    smtp_pass = os.getenv("SMTP_PASSWORD") or os.getenv("EMAIL_PASS")
    use_tls = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    # If host missing but Gmail creds provided, default to Gmail
    if not smtp_host and os.getenv("EMAIL_ADDRESS"):
        smtp_host = "smtp.gmail.com"
        smtp_port = 587
        use_tls = True
    from_email = os.getenv("EMAIL_FROM") or smtp_user

    print(f"Debug: SMTP config - host={smtp_host}, port={smtp_port}, user={smtp_user}, tls={use_tls}")
    print(f"Debug: From={from_email}, To={to_email}")

    if not all([smtp_host, smtp_port, smtp_user, smtp_pass, from_email]):
        raise RuntimeError("SMTP configuration is incomplete. Provide Gmail EMAIL_ADDRESS/EMAIL_PASS or full SMTP_* vars.")

    subject = "Your Agenagn verification code"
    body = (
        f"Hello,\n\n"
        f"Your verification code is: {code}\n\n"
        f"It expires in 15 minutes.\n\n"
        f"If you didn't request this, you can ignore this email.\n"
    )

    message = MIMEMultipart()
    message["From"] = from_email
    message["To"] = to_email
    message["Subject"] = subject
    message.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
            print(f"Debug: Connected to {smtp_host}:{smtp_port}")
            if use_tls:
                server.starttls()
                print("Debug: TLS started")
            server.login(smtp_user, smtp_pass)
            print("Debug: Login successful")
            server.sendmail(from_email, to_email, message.as_string())
            print("Debug: Email sent successfully")
    except Exception as e:
        print(f"Debug: SMTP error: {e}")
        raise


def test_env_vars():
    """Test function to check environment variables"""
    print("=== Environment Variables Test ===")
    print(f"EMAIL_ADDRESS: {os.getenv('EMAIL_ADDRESS')}")
    print(f"EMAIL_PASS: {os.getenv('EMAIL_PASS')}")
    print(f"All env vars: {dict(os.environ)}")
    print("==================================")