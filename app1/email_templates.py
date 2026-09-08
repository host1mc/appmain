"""
email_templates.py — Production-grade, responsive, high-profile HTML email templates.

Provides modern dark-themed HTML and plaintext email bodies for OTP verification,
welcome onboarding, trial warnings, trial stopped notices, and security alerts.
"""

import html as _html
import renew_config

BRAND_NAME = getattr(renew_config, "BRAND_NAME", "MC Status")
BRAND_INITIALS = getattr(renew_config, "BRAND_INITIALS", "MC")

# Theme Color Tokens
_BG_DARK = "#09090b"        # Zinc 950
_CARD_BG = "#18181b"        # Zinc 900
_BORDER_COLOR = "#27272a"   # Zinc 800
_TEXT_MAIN = "#f4f4f5"      # Zinc 100
_TEXT_MUTED = "#a1a1aa"     # Zinc 400
_TEXT_SUBTLE = "#71717a"    # Zinc 500
_PURPLE_PRIMARY = "#8b5cf6" # Violet 500
_PURPLE_DARK = "#6d28d9"    # Violet 700
_PURPLE_LIGHT = "#a855f7"   # Purple 500


def _wrap_email_layout(subject_title, content_html, footer_note=None):
    """Wrap email body content inside a high-profile production dark layout."""
    subject_safe = _html.escape(str(subject_title or ""))
    note_safe = _html.escape(str(footer_note)) if footer_note else f"This is an automated security notice from <strong style='color:{_PURPLE_LIGHT};'>{_html.escape(BRAND_NAME)}</strong>."

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{subject_safe}</title>
</head>
<body style="margin:0; padding:0; background-color:{_BG_DARK}; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing:antialiased;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:{_BG_DARK}; padding:40px 16px;">
    <tr>
      <td align="center">
        <table role="presentation" width="580" cellpadding="0" cellspacing="0" style="max-width:580px; width:100%;">
          
          <!-- Header Logo -->
          <tr>
            <td style="padding:0 0 28px; text-align:center;">
              <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;">
                <tr>
                  <td style="width:44px; height:44px; border-radius:12px; background:linear-gradient(135deg, {_PURPLE_LIGHT}, {_PURPLE_DARK}); text-align:center; vertical-align:middle; font-size:20px; font-weight:800; color:#ffffff; line-height:44px; box-shadow:0 4px 14px rgba(109,40,217,0.4);">{_html.escape(BRAND_INITIALS)}</td>
                  <td style="padding-left:14px; font-size:24px; font-weight:800; color:{_TEXT_MAIN}; letter-spacing:-0.5px;">{_html.escape(BRAND_NAME)}</td>
                </tr>
              </table>
            </td>
          </tr>

          <!-- Main Content Card -->
          <tr>
            <td style="background-color:{_CARD_BG}; border:1px solid {_BORDER_COLOR}; border-radius:16px; padding:40px 36px; box-shadow:0 12px 32px rgba(0,0,0,0.6);">
              {content_html}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:24px 12px 0; text-align:center; font-size:12px; color:{_TEXT_SUBTLE}; line-height:1.6;">
              {note_safe}<br>
              &copy; {_html.escape(BRAND_NAME)}. All rights reserved. Keep your credentials private.
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def build_otp_email(to_addr, code, purpose="verification", expire_minutes=10):
    """Build high-profile OTP email template (Argon2-encrypted at rest)."""
    code_safe = _html.escape(str(code or "").strip())
    subject = f"{code_safe} is your {BRAND_NAME} verification code"
    
    plain_text = (
        f"Your {BRAND_NAME} verification code is: {code_safe}\n\n"
        f"It expires in {expire_minutes} minutes. "
        f"Do not share this code with anyone."
    )

    content_html = f"""
      <h1 style="margin:0 0 10px; font-size:22px; font-weight:700; color:{_TEXT_MAIN}; text-align:center;">Security Verification Code</h1>
      <p style="margin:0 0 24px; font-size:14px; color:{_TEXT_MUTED}; text-align:center; line-height:1.5;">
        Use the verification code below to authorize your <strong>{_html.escape(purpose.capitalize())}</strong> request.
      </p>

      <!-- OTP Code Box -->
      <div style="background-color:{_BG_DARK}; border:1px solid {_BORDER_COLOR}; border-radius:12px; padding:24px; text-align:center; margin-bottom:24px;">
        <span style="font-family:'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size:36px; font-weight:800; color:{_PURPLE_LIGHT}; letter-spacing:12px; display:inline-block; padding-left:12px;">{code_safe}</span>
      </div>

      <div style="text-align:center; margin-bottom:12px;">
        <span style="display:inline-block; background-color:rgba(139,92,246,0.15); border:1px solid rgba(139,92,246,0.3); border-radius:20px; padding:6px 16px; font-size:12px; font-weight:600; color:{_PURPLE_LIGHT};">
          ⏳ Valid for {expire_minutes} minutes
        </span>
      </div>

      <p style="margin:20px 0 0; font-size:13px; color:{_TEXT_SUBTLE}; text-align:center; line-height:1.5;">
        If you did not request this code, please ignore this email or secure your account.
      </p>
    """

    html_body = _wrap_email_layout(subject, content_html)
    return subject, plain_text, html_body


def build_welcome_email(to_addr, username):
    """Build high-profile Welcome Onboarding email template."""
    user_safe = _html.escape(str(username or "there"))
    subject = f"Welcome to {BRAND_NAME}, {user_safe}!"

    plain_text = (
        f"Welcome to {BRAND_NAME}, {user_safe}!\n\n"
        f"Your account is verified and ready to go.\n\n"
        f"Next steps:\n"
        f"- Add your Discord bot token\n"
        f"- Configure server IP & port\n"
        f"- Customise your status embed\n"
        f"- Deploy & launch!"
    )

    content_html = f"""
      <h1 style="margin:0 0 8px; font-size:22px; font-weight:700; color:{_TEXT_MAIN};">Welcome to {_html.escape(BRAND_NAME)}, {user_safe}! 👋</h1>
      <p style="margin:0 0 24px; font-size:14px; color:{_TEXT_MUTED}; line-height:1.6;">
        Your account is verified and ready. You can now deploy high-performance Minecraft Discord status bots and manage your containers.
      </p>

      <!-- Checklist Card -->
      <div style="background-color:{_BG_DARK}; border:1px solid {_BORDER_COLOR}; border-radius:12px; padding:20px 24px; margin-bottom:28px;">
        <h3 style="margin:0 0 12px; font-size:14px; font-weight:700; color:{_PURPLE_LIGHT}; text-transform:uppercase; letter-spacing:0.5px;">Getting Started Checklist:</h3>
        <ul style="margin:0; padding:0 0 0 18px; color:{_TEXT_MAIN}; font-size:14px; line-height:1.8;">
          <li>Add your Discord Bot Token</li>
          <li>Set your Minecraft Server IP &amp; Port</li>
          <li>Customize your live status embed design</li>
          <li>Deploy &amp; launch your container!</li>
        </ul>
      </div>

      <div style="text-align:center;">
        <a href="#" style="display:inline-block; background:linear-gradient(135deg, {_PURPLE_PRIMARY}, {_PURPLE_DARK}); color:#ffffff; font-size:14px; font-weight:700; text-decoration:none; padding:14px 32px; border-radius:10px; box-shadow:0 4px 16px rgba(109,40,217,0.4);">
          Open Control Panel &rarr;
        </a>
      </div>
    """

    html_body = _wrap_email_layout(subject, content_html)
    return subject, plain_text, html_body


def build_trial_warning_email(to_addr, username, days_left, expiry_date_str=""):
    """Build high-profile Trial Warning email template."""
    user_safe = _html.escape(str(username or "there"))
    days = max(1, int(days_left or 1))
    subject = f"Renew your trial in {days} day{'s' if days != 1 else ''}"

    plain_text = (
        f"Hi {user_safe},\n\n"
        f"Your trial renewal window is open. Renew before it expires in {days} day(s) "
        f"to keep your containers and status embeds running without interruption.\n\n"
        f"Log in to your dashboard and click Renew."
    )

    date_clause = f" on <strong>{_html.escape(expiry_date_str)}</strong>" if expiry_date_str else ""

    content_html = f"""
      <h1 style="margin:0 0 10px; font-size:22px; font-weight:700; color:{_TEXT_MAIN};">Trial Renewal Open ⏰</h1>
      <p style="margin:0 0 20px; font-size:14px; color:{_TEXT_MUTED}; line-height:1.6;">
        Hi <strong>{user_safe}</strong>, your current trial cycle ends{date_clause} (in {days} day{'s' if days != 1 else ''}).
      </p>

      <div style="background-color:rgba(139,92,246,0.1); border:1px solid rgba(139,92,246,0.25); border-radius:12px; padding:20px 24px; margin-bottom:28px;">
        <p style="margin:0; font-size:14px; color:{_TEXT_MAIN}; line-height:1.6;">
          Click <strong>Renew</strong> on your control panel to extend your trial clock by another full cycle. Renewal is quick and keeps your bots and containers running seamlessly.
        </p>
      </div>

      <div style="text-align:center;">
        <a href="#" style="display:inline-block; background:linear-gradient(135deg, {_PURPLE_PRIMARY}, {_PURPLE_DARK}); color:#ffffff; font-size:14px; font-weight:700; text-decoration:none; padding:14px 32px; border-radius:10px; box-shadow:0 4px 16px rgba(109,40,217,0.4);">
          Renew Trial Now &rarr;
        </a>
      </div>
    """

    html_body = _wrap_email_layout(subject, content_html)
    return subject, plain_text, html_body


def build_trial_stopped_email(to_addr, username, assets="Your bot and containers"):
    """Build high-profile Trial Stopped email template."""
    user_safe = _html.escape(str(username or "there"))
    assets_safe = _html.escape(str(assets or "Your bot and containers"))
    subject = f"Your trial expired — {assets_safe} stopped"

    plain_text = (
        f"Hi {user_safe},\n\n"
        f"Your trial expired today and {assets_safe} have been stopped.\n\n"
        f"Log in to your dashboard and renew your account to reactivate your workloads."
    )

    content_html = f"""
      <h1 style="margin:0 0 10px; font-size:22px; font-weight:700; color:{_TEXT_MAIN};">Trial Expired &amp; Workloads Paused</h1>
      <p style="margin:0 0 20px; font-size:14px; color:{_TEXT_MUTED}; line-height:1.6;">
        Hi <strong>{user_safe}</strong>, your trial expired today and <strong>{assets_safe}</strong> have been safely paused.
      </p>

      <div style="background-color:{_BG_DARK}; border:1px solid {_BORDER_COLOR}; border-radius:12px; padding:20px 24px; margin-bottom:28px;">
        <p style="margin:0; font-size:14px; color:{_TEXT_MAIN}; line-height:1.6;">
          You can log in to your control panel at any time and click <strong>Renew</strong> to restore your workloads and reactivate your bots.
        </p>
      </div>

      <div style="text-align:center;">
        <a href="#" style="display:inline-block; background:linear-gradient(135deg, {_PURPLE_PRIMARY}, {_PURPLE_DARK}); color:#ffffff; font-size:14px; font-weight:700; text-decoration:none; padding:14px 32px; border-radius:10px; box-shadow:0 4px 16px rgba(109,40,217,0.4);">
          Reactivate Workloads &rarr;
        </a>
      </div>
    """

    html_body = _wrap_email_layout(subject, content_html)
    return subject, plain_text, html_body


def build_security_alert_email(to_addr, username, event_type, details=None):
    """Build high-profile Security Alert email template."""
    user_safe = _html.escape(str(username or "user"))
    event_safe = _html.escape(str(event_type or "Security Notice"))
    subject = f"Security Alert: {event_safe} detected for {user_safe}"

    details_str = _html.escape(str(details)) if details else "A security event was flagged for your account."

    plain_text = (
        f"Security Alert for {user_safe}:\n\n"
        f"Event: {event_safe}\n"
        f"Details: {details_str}\n\n"
        f"If this was not you, please secure your account immediately."
    )

    content_html = f"""
      <h1 style="margin:0 0 10px; font-size:22px; font-weight:700; color:#ef4444;">Security Alert 🛡️</h1>
      <p style="margin:0 0 20px; font-size:14px; color:{_TEXT_MUTED}; line-height:1.6;">
        A security event was recorded for account <strong>{user_safe}</strong>.
      </p>

      <div style="background-color:{_BG_DARK}; border:1px solid #7f1d1d; border-radius:12px; padding:20px 24px; margin-bottom:28px;">
        <p style="margin:0 0 8px; font-size:13px; font-weight:700; color:#f87171; text-transform:uppercase;">Event Type: {event_safe}</p>
        <p style="margin:0; font-size:13px; color:{_TEXT_MAIN}; font-family:monospace; word-break:break-all;">{details_str}</p>
      </div>

      <p style="margin:0; font-size:13px; color:{_TEXT_SUBTLE}; text-align:center;">
        If you did not authorize this action, please reset your password immediately.
      </p>
    """

    html_body = _wrap_email_layout(subject, content_html, footer_note="Security & Anti-Abuse Notification")
    return subject, plain_text, html_body
