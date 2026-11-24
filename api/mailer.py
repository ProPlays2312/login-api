def send_otp_email(to_email, otp_code, username=None):
    """Send an OTP email using SMTP (Gmail, Outlook, custom) or Plunk email delivery.

    Reads configuration from environment variables:
    - ``SMTP_EMAIL`` / ``SMTP_PASSWORD``: Direct SMTP credentials (e.g., Gmail App Password).
    - ``SMTP_HOST`` / ``SMTP_PORT``: SMTP host (default: ``smtp.gmail.com``) and port (default: ``587``).
    - ``PLUNK_API_KEY``: API key for Plunk email delivery service.
    - ``PLUNK_FROM``: Sender address for Plunk (e.g., ``Vault Auth <no-reply@vaultauthsso.proplays2312.eu.org>``).

    Returns:
        tuple[bool, Optional[str]]: (True, None) on success, or (False, error_message) on failure.
    """
    import os
    import json
    import html
    import email.utils
    import urllib.request
    import urllib.error
    from api.utils import safe_print

    smtp_user = os.getenv("SMTP_EMAIL") or os.getenv("SMTP_USER") or os.getenv("GMAIL_USER")
    smtp_pass = os.getenv("SMTP_PASSWORD") or os.getenv("SMTP_APP_PASSWORD") or os.getenv("SMTP_PASS") or os.getenv("GMAIL_APP_PASSWORD")
    plunk_key = os.getenv("PLUNK_API_KEY")

    if not (smtp_user and smtp_pass) and not (plunk_key and plunk_key.strip()):
        return False, "Email delivery not configured. Add SMTP_EMAIL + SMTP_PASSWORD or PLUNK_API_KEY to .env."

    raw_display = username or to_email
    display_name = html.escape(str(raw_display))
    safe_otp = html.escape(str(otp_code))
    subject = f"{otp_code} is your Vault Auth verification code"

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset=\"utf-8\"/>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #0f172a;
      color: #f8fafc;
      margin: 0;
      padding: 30px;
    }}
    .container {{ max-width: 500px; margin: 0 auto; background: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    .header {{ text-align: center; margin-bottom: 24px; }}
    .brand {{ font-size: 24px; font-weight: 700; letter-spacing: -0.5px; color: #38bdf8; }}
    .title {{ font-size: 18px; color: #e2e8f0; margin-top: 8px; font-weight: 600; }}
    .otp-box {{ margin: 28px 0; text-align: center; background: #0f172a; border: 2px dashed #38bdf8; border-radius: 10px; padding: 18px; }}
    .otp-code {{ font-size: 36px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; font-family: 'SF Mono', Consolas, Monaco, monospace; }}
    .info {{ font-size: 14px; color: #94a3b8; line-height: 1.6; margin-top: 16px; }}
    .footer {{ margin-top: 28px; padding-top: 16px; border-top: 1px solid #334155; font-size: 12px; color: #64748b; text-align: center; }}
  </style>
</head>
<body>
  <div class=\"container\">
    <div class=\"header\">
      <div class=\"brand\">Vault Auth</div>
      <div class=\"title\">Verification Code</div>
    </div>
    <p class=\"info\">Hello <strong>{display_name}</strong>,</p>
    <p class=\"info\">Use the following One-Time Password (OTP) to complete your login. This code is confidential and valid for <strong>5 minutes</strong>.</p>
    <div class=\"otp-box\"><div class=\"otp-code\">{safe_otp}</div></div>
    <p class=\"info\">If you didn't request this login code, you can safely ignore this email.</p>
    <div class=\"footer\">&copy; Vault Auth Security &bull; Automated security notification</div>
  </div>
</body>
</html>
"""

    # 1. SMTP Delivery (if SMTP credentials are provided)
    if smtp_user and smtp_pass:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587") or 587)
        from_header = os.getenv("SMTP_FROM", f"Vault Auth <{smtp_user}>")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_header
        msg["To"] = to_email

        text_content = f"Vault Auth - Verification Code\n\nHello {raw_display},\n\nYour login verification code is: {otp_code}\n\nThis code is valid for 5 minutes.\nIf you did not request this, please ignore this email."
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            safe_print(f"[SMTP Success] OTP email sent to {to_email}")
            return True, None
        except Exception as e:
            safe_print(f"[SMTP Error] {e}")
            if not plunk_key:
                return False, f"SMTP delivery failed: {e}"

    # 2. Plunk API Delivery (fallback or primary when PLUNK_API_KEY is set)
    plunk_from = os.getenv("PLUNK_FROM", "Vault Auth <no-reply@vaultauthsso.proplays2312.eu.org>")
    sender_name, sender_addr = email.utils.parseaddr(plunk_from)
    sender_addr = sender_addr.strip() if sender_addr else plunk_from.strip()
    sender_name = sender_name.strip() if sender_name else "Vault Auth"

    payload = {
        "to": to_email,
        "subject": subject,
        "body": html_content,
        "from": sender_addr,
        "name": sender_name,
    }

    req = urllib.request.Request(
        "https://next-api.useplunk.com/v1/send",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {plunk_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "VaultAuth/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            safe_print(f"[Plunk] OTP email successfully sent to {to_email}")
            return True, None
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode("utf-8"))
            err_msg = err_body.get("message") or err_body.get("error") or str(err_body)
        except Exception:
            err_msg = str(e)
        safe_print(f"[Plunk Error] {e.code}: {err_msg}")
        return False, f"Plunk error: {err_msg}"
    except urllib.error.URLError as e:
        safe_print(f"[Plunk URLError] {e}")
        return False, f"Plunk network error: {e}"
    except Exception as e:
        safe_print(f"[Plunk Error] {e}")
        return False, f"Plunk dispatch failed: {e}"


def send_password_reset_email(to_email, reset_code_or_link, username=None):
    """Send a password reset instructions email using SMTP or Plunk."""
    import os
    import json
    import html
    import email.utils
    import urllib.request
    import urllib.error
    from api.utils import safe_print

    smtp_user = os.getenv("SMTP_EMAIL") or os.getenv("SMTP_USER") or os.getenv("GMAIL_USER")
    smtp_pass = os.getenv("SMTP_PASSWORD") or os.getenv("SMTP_APP_PASSWORD") or os.getenv("SMTP_PASS") or os.getenv("GMAIL_APP_PASSWORD")
    plunk_key = os.getenv("PLUNK_API_KEY")

    if not (smtp_user and smtp_pass) and not (plunk_key and plunk_key.strip()):
        return False, "Email delivery not configured. Add SMTP_EMAIL + SMTP_PASSWORD or PLUNK_API_KEY to .env."

    raw_display = username or to_email
    display_name = html.escape(str(raw_display))
    safe_code = html.escape(str(reset_code_or_link))
    subject = "Vault Auth Password Reset Request"

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset=\"utf-8\"/>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #0f172a;
      color: #f8fafc;
      margin: 0;
      padding: 30px;
    }}
    .container {{ max-width: 500px; margin: 0 auto; background: #1e293b; border-radius: 12px; border: 1px solid #334155; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    .header {{ text-align: center; margin-bottom: 24px; }}
    .brand {{ font-size: 24px; font-weight: 700; letter-spacing: -0.5px; color: #38bdf8; }}
    .title {{ font-size: 18px; color: #e2e8f0; margin-top: 8px; font-weight: 600; }}
    .code-box {{ margin: 28px 0; text-align: center; background: #0f172a; border: 2px dashed #38bdf8; border-radius: 10px; padding: 18px; }}
    .code-text {{ font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #38bdf8; font-family: 'SF Mono', Consolas, Monaco, monospace; }}
    .info {{ font-size: 14px; color: #94a3b8; line-height: 1.6; margin-top: 16px; }}
    .footer {{ margin-top: 28px; padding-top: 16px; border-top: 1px solid #334155; font-size: 12px; color: #64748b; text-align: center; }}
  </style>
</head>
<body>
  <div class=\"container\">
    <div class=\"header\">
      <div class=\"brand\">Vault Auth</div>
      <div class=\"title\">Password Reset Request</div>
    </div>
    <p class=\"info\">Hello <strong>{display_name}</strong>,</p>
    <p class=\"info\">We received a request to reset your password. Use the verification code below to reset your password. This code will expire in <strong>15 minutes</strong>.</p>
    <div class=\"code-box\"><div class=\"code-text\">{safe_code}</div></div>
    <p class=\"info\">If you did not request a password reset, you can safely disregard this email. Your password will remain unchanged.</p>
    <div class=\"footer\">&copy; Vault Auth Security &bull; Automated security notification</div>
  </div>
</body>
</html>
"""

    # 1. SMTP Delivery
    if smtp_user and smtp_pass:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587") or 587)
        from_header = os.getenv("SMTP_FROM", f"Vault Auth <{smtp_user}>")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_header
        msg["To"] = to_email

        text_content = f"Vault Auth - Password Reset\n\nHello {raw_display},\n\nYour password reset code is: {reset_code_or_link}\nValid for 15 minutes."
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(smtp_user, smtp_pass)
                server.send_message(msg)
            safe_print(f"[SMTP Success] Password reset email sent to {to_email}")
            return True, None
        except Exception as e:
            safe_print(f"[SMTP Error] {e}")
            if not plunk_key:
                return False, f"SMTP delivery failed: {e}"

    # 2. Plunk Delivery
    plunk_from = os.getenv("PLUNK_FROM", "Vault Auth <no-reply@vaultauthsso.proplays2312.eu.org>")
    sender_name, sender_addr = email.utils.parseaddr(plunk_from)
    sender_addr = sender_addr.strip() if sender_addr else plunk_from.strip()
    sender_name = sender_name.strip() if sender_name else "Vault Auth"

    payload = {
        "to": to_email,
        "subject": subject,
        "body": html_content,
        "from": sender_addr,
        "name": sender_name,
    }

    req = urllib.request.Request(
        "https://next-api.useplunk.com/v1/send",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {plunk_key.strip()}",
            "Content-Type": "application/json",
            "User-Agent": "VaultAuth/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            safe_print(f"[Plunk] Password reset email sent to {to_email}")
            return True, None
    except Exception as e:
        safe_print(f"[Plunk Error] Password reset send failed: {e}")
        return False, str(e)

