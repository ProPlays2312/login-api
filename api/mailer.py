# Description: Service to dispatch real OTP emails via Resend API or Gmail SMTP.

import smtplib
import urllib.request
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from pathlib import Path
from dotenv import load_dotenv
from api.utils import safe_print

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
load_dotenv()


def send_otp_email(to_email, otp_code, username=None):
    """
    Sends a real OTP verification email using Resend API or Gmail SMTP.
    Requires RESEND_API_KEY or (SMTP_EMAIL and SMTP_APP_PASSWORD) in .env.
    """
    resend_api_key = os.getenv("RESEND_API_KEY")
    gmail_user = (
        os.getenv("SMTP_EMAIL")
        or os.getenv("GMAIL_USER")
        or os.getenv("SMTP_USER")
    )
    gmail_pass = (
        os.getenv("SMTP_APP_PASSWORD")
        or os.getenv("GMAIL_APP_PASSWORD")
        or os.getenv("SMTP_PASSWORD")
    )

    display_name = username or to_email
    subject = f"{otp_code} is your Vault Auth verification code"

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background-color: #0f172a;
      color: #f8fafc;
      margin: 0;
      padding: 30px;
    }}
    .container {{
      max-width: 500px;
      margin: 0 auto;
      background: #1e293b;
      border-radius: 12px;
      border: 1px solid #334155;
      padding: 32px;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
    }}
    .header {{
      text-align: center;
      margin-bottom: 24px;
    }}
    .brand {{
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.5px;
      color: #38bdf8;
    }}
    .title {{
      font-size: 18px;
      color: #e2e8f0;
      margin-top: 8px;
      font-weight: 600;
    }}
    .otp-box {{
      margin: 28px 0;
      text-align: center;
      background: #0f172a;
      border: 2px dashed #38bdf8;
      border-radius: 10px;
      padding: 18px;
    }}
    .otp-code {{
      font-size: 36px;
      font-weight: 800;
      letter-spacing: 8px;
      color: #38bdf8;
      font-family: 'SF Mono', Consolas, Monaco, monospace;
    }}
    .info {{
      font-size: 14px;
      color: #94a3b8;
      line-height: 1.6;
      margin-top: 16px;
    }}
    .footer {{
      margin-top: 28px;
      padding-top: 16px;
      border-top: 1px solid #334155;
      font-size: 12px;
      color: #64748b;
      text-align: center;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">Vault Auth</div>
      <div class="title">Verification Code</div>
    </div>
    <p class="info">Hello <strong>{display_name}</strong>,</p>
    <p class="info">Use the following One-Time Password (OTP) to complete your login. This code is confidential and valid for <strong>5 minutes</strong>.</p>

    <div class="otp-box">
      <div class="otp-code">{otp_code}</div>
    </div>

    <p class="info">If you didn't request this login code, you can safely ignore this email. Someone may have typed your email address by mistake.</p>

    <div class="footer">
      &copy; Vault Auth Security &bull; Automated security notification
    </div>
  </div>
</body>
</html>"""

    text_content = f"""Vault Auth - Verification Code

Hello {display_name},

Your login verification code is: {otp_code}

This code is valid for 5 minutes.
If you did not request this, please ignore this email.
"""

# 1. Gmail SMTP — tried FIRST when credentials are present (can send to ANY recipient)
    if gmail_user and gmail_pass:
        safe_print(f"[Gmail SMTP] Attempting to send OTP to {to_email} using SMTP credentials from .env")
        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        smtp_port = int(os.getenv("SMTP_PORT", "587") or 587)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"Vault Auth <{gmail_user}>"
        msg["To"] = to_email

        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(gmail_user, gmail_pass)
                server.send_message(msg)

            safe_print(f"[Gmail SMTP Success] OTP email successfully sent to {to_email}")
            return True, None
        except smtplib.SMTPAuthenticationError as e:
            err = f"Gmail Authentication failed. Check your App Password in .env: {e}"
            safe_print(f"[Gmail SMTP Error] {err}")
            return False, err
        except Exception as e:
            err = f"Gmail SMTP failed: {e}"
            safe_print(f"[Gmail SMTP Error] {err}")
            # Do NOT fall through to Resend – credentials exist but SMTP error occurred
            return False, err

    # 2. Resend API — fallback when only RESEND_API_KEY is set (free tier: owner email only)
    if resend_api_key and not (gmail_user and gmail_pass):
        resend_from = os.getenv("RESEND_FROM", "Vault Auth <onboarding@resend.dev>")
        payload = {
            "from": resend_from,
            "to": [to_email],
            "subject": subject,
            "html": html_content,
            "text": text_content,
        }
        req = urllib.request.Request(
            "https://api.resend.com/emails",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {resend_api_key.strip()}",
                "Content-Type": "application/json",
                "User-Agent": "VaultAuth/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                safe_print(f"[Resend Success] Sent OTP email to {to_email}")
                return True, None
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
                err_msg = err_body.get("message") or str(err_body)
            except Exception:
                err_msg = str(e)
            safe_print(f"[Resend Error] {e.code}: {err_msg}")
            return False, f"Resend error: {err_msg}"
        except Exception as e:
            safe_print(f"[Resend Error] {e}")
            return False, f"Resend dispatch failed: {e}"

    # 3. No credentials configured at all
    return False, "Email delivery not configured. Add SMTP_EMAIL + SMTP_APP_PASSWORD to .env for full delivery."
