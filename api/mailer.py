def send_otp_email(to_email, otp_code, username=None):
    """Send an OTP email using Plunk as the dedicated email delivery service.

    Reads configuration from environment variables:
    - ``PLUNK_API_KEY``: Secret key for authenticating with Plunk's API.
    - ``PLUNK_FROM``: Sender address (e.g., ``Vault Auth <no-reply@vaultauthsso.proplays2312.eu.org>``).

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

    plunk_key = os.getenv("PLUNK_API_KEY")
    if not plunk_key or not plunk_key.strip():
        return False, "Email delivery not configured. Add PLUNK_API_KEY to .env."

    plunk_from = os.getenv("PLUNK_FROM", "Vault Auth <no-reply@vaultauthsso.proplays2312.eu.org>")
    sender_name, sender_addr = email.utils.parseaddr(plunk_from)
    sender_addr = sender_addr.strip() if sender_addr else plunk_from.strip()
    sender_name = sender_name.strip() if sender_name else "Vault Auth"

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
