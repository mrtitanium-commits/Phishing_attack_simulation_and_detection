"""
Email Generator Module
======================
Generates realistic phishing simulation emails for security awareness testing.

This module creates simulated phishing emails with various templates and
sophistication levels. All generated emails are clearly marked as simulations
and should ONLY be used in authorized testing environments.

Techniques Demonstrated:
- Email spoofing (header manipulation)
- Social engineering tactics (urgency, authority, fear)
- Brand impersonation
- Tracking pixel insertion
- Phishing link creation
"""

import uuid
import html
import hashlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum


class SophisticationLevel(Enum):
    """Sophistication levels for phishing emails."""
    BASIC = "basic"           # Obvious spelling errors, generic greeting
    INTERMEDIATE = "intermediate"  # Better grammar, some personalization
    ADVANCED = "advanced"     # Perfect grammar, highly personalized, convincing


class TemplateType(Enum):
    """Types of phishing email templates."""
    PASSWORD_RESET = "password_reset"
    INVOICE = "invoice"
    ACCOUNT_VERIFICATION = "account_verification"
    PRIZE_WINNER = "prize_winner"
    IT_SUPPORT = "it_support"
    CEO_FRAUD = "ceo_fraud"
    DELIVERY_NOTIFICATION = "delivery_notification"
    SOCIAL_MEDIA = "social_media"


@dataclass
class PhishingEmail:
    """Data class representing a generated phishing email."""
    email_id: str
    template_type: str
    subject: str
    body_html: str
    body_text: str
    sender_name: str
    sender_email: str
    target_name: str
    target_email: str
    headers: Dict[str, str] = field(default_factory=dict)
    sophistication: str = "intermediate"
    campaign_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    tracking_pixel_id: Optional[str] = None
    phishing_link_id: Optional[str] = None


class PhishingEmailGenerator:
    """
    Generates realistic phishing simulation emails for security testing.

    This generator creates emails that mimic common phishing attack patterns
    for the purpose of testing organizational security awareness.

    Attributes:
        tracking_domain: Domain used for tracking pixel callbacks
        landing_domain: Domain used for phishing landing pages
    """

    def __init__(self, tracking_domain="http://localhost:5000/track",
                 landing_domain="http://localhost:5000/landing"):
        self.tracking_domain = tracking_domain
        self.landing_domain = landing_domain

        # Template registry mapping types to generator methods
        self._templates = {
            "password_reset": self._template_password_reset,
            "invoice": self._template_invoice,
            "account_verification": self._template_account_verification,
            "prize_winner": self._template_prize_winner,
            "it_support": self._template_it_support,
            "ceo_fraud": self._template_ceo_fraud,
            "delivery_notification": self._template_delivery_notification,
            "social_media": self._template_social_media,
        }

    def generate_email(
        self,
        template_type: str,
        target_name: str,
        target_email: str,
        sender_org: str = "SecureCorp",
        sophistication: str = "intermediate",
        campaign_id: Optional[str] = None,
    ) -> PhishingEmail:
        """
        Generate a phishing simulation email.

        Args:
            template_type: Type of phishing template to use
            target_name: Name of the target recipient
            target_email: Email address of the target
            sender_org: Organization name to impersonate
            sophistication: Level of sophistication (basic/intermediate/advanced)
            campaign_id: Optional campaign identifier for tracking

        Returns:
            PhishingEmail dataclass with all email components

        Raises:
            ValueError: If template_type is not recognized
        """
        if template_type not in self._templates:
            raise ValueError(
                f"Unknown template type: {template_type}. "
                f"Available: {list(self._templates.keys())}"
            )

        email_id = str(uuid.uuid4())
        target_id = hashlib.md5(target_email.encode()).hexdigest()[:12]
        c_id = campaign_id or str(uuid.uuid4())[:8]

        # Generate base email content from template
        template_func = self._templates[template_type]
        subject, body_html, body_text, sender_name, sender_email = template_func(
            target_name, target_email, sender_org
        )

        # Apply sophistication-based modifications
        if sophistication == "basic":
            body_html = self._degrade_quality(body_html)
            body_text = self._degrade_quality(body_text)
        elif sophistication == "advanced":
            body_html = self._enhance_quality(body_html, target_name, sender_org)
            body_text = self._enhance_quality(body_text, target_name, sender_org)

        # Apply urgency tactics based on sophistication
        urgency_map = {"basic": "high", "intermediate": "medium", "advanced": "low"}
        urgency = urgency_map.get(sophistication, "medium")
        body_html = self._apply_urgency_tactics(body_html, urgency)
        body_text = self._apply_urgency_tactics(body_text, urgency)

        # Insert tracking pixel
        tracking_pixel_id = f"{c_id}-{target_id}"
        body_html = self._insert_tracking_pixel(body_html, c_id, target_id)

        # Create phishing link
        phishing_link = self._create_phishing_link(
            f"https://{sender_org.lower().replace(' ', '')}.com/account",
            c_id, target_id
        )
        body_html = body_html.replace("{{phishing_link}}", phishing_link)
        body_text = body_text.replace("{{phishing_link}}", phishing_link)

        # Generate spoofed headers
        headers = self._spoof_headers(sender_org, sender_email, target_email)

        return PhishingEmail(
            email_id=email_id,
            template_type=template_type,
            subject=subject,
            body_html=body_html,
            body_text=body_text,
            sender_name=sender_name,
            sender_email=sender_email,
            target_name=target_name,
            target_email=target_email,
            headers=headers,
            sophistication=sophistication,
            campaign_id=c_id,
            tracking_pixel_id=tracking_pixel_id,
            phishing_link_id=f"{c_id}-{target_id}",
        )

    def get_available_templates(self) -> List[str]:
        """Return list of available template types."""
        return list(self._templates.keys())

    # -------------------------------------------------------------------------
    # Urgency and modification methods
    # -------------------------------------------------------------------------

    def _apply_urgency_tactics(self, content: str, level: str) -> str:
        """
        Apply urgency tactics to email content.

        Social Engineering Concept:
            Urgency is a key psychological manipulation tactic. Attackers
            create time pressure to prevent victims from thinking critically.

        Args:
            content: Email body content
            level: Urgency level (low/medium/high)

        Returns:
            Modified content with urgency elements
        """
        urgency_additions = {
            "high": [
                "\n\n⚠️ URGENT: Immediate action required!",
                "\n⚠️ Your account will be suspended within 2 hours.",
                "\n⚠️ FINAL WARNING: Act now to prevent data loss!",
            ],
            "medium": [
                "\n\nPlease complete this action within 24 hours.",
                "\nThis request expires soon. Please respond promptly.",
            ],
            "low": [
                "\n\nPlease take action at your earliest convenience.",
            ],
        }

        additions = urgency_additions.get(level, urgency_additions["medium"])
        # Use deterministic selection based on content length
        selected = additions[len(content) % len(additions)]
        return content + selected

    def _insert_tracking_pixel(self, html_content: str, campaign_id: str,
                                target_id: str) -> str:
        """
        Insert an invisible tracking pixel into HTML email.

        Security Concept:
            Tracking pixels are 1x1 transparent images that load from a
            remote server when the email is opened, allowing attackers to
            know when and where an email was read.

        Args:
            html_content: HTML email body
            campaign_id: Campaign identifier
            target_id: Target identifier

        Returns:
            HTML with tracking pixel inserted before closing body/html tag
        """
        pixel_url = f"{self.tracking_domain}/{campaign_id}/{target_id}/open.png"
        pixel_tag = (
            f'<img src="{pixel_url}" width="1" height="1" '
            f'alt="" style="display:none;visibility:hidden;" />'
        )

        # Insert before closing tags
        if "</body>" in html_content:
            return html_content.replace("</body>", f"{pixel_tag}</body>")
        elif "</html>" in html_content:
            return html_content.replace("</html>", f"{pixel_tag}</html>")
        else:
            return html_content + pixel_tag

    def _create_phishing_link(self, legitimate_url: str, campaign_id: str,
                               target_id: str) -> str:
        """
        Create a trackable phishing link that mimics a legitimate URL.

        Security Concept:
            Phishing links often look similar to legitimate URLs but redirect
            through an attacker-controlled server. This allows tracking of
            clicks and delivery of fake login pages.

        Args:
            legitimate_url: The URL being impersonated
            campaign_id: Campaign identifier
            target_id: Target identifier

        Returns:
            Phishing URL that routes through the tracking/landing system
        """
        return (
            f"{self.landing_domain}/{campaign_id}/{target_id}"
            f"?redirect={legitimate_url}"
        )

    def _spoof_headers(self, sender_org: str, sender_email: str,
                        target_email: str) -> Dict[str, str]:
        """
        Generate spoofed email headers for simulation.

        Security Concept:
            Email header spoofing allows attackers to make emails appear
            to come from trusted senders. SPF, DKIM, and DMARC are
            authentication mechanisms designed to prevent this.

        Args:
            sender_org: Organization name to impersonate
            sender_email: Spoofed sender email
            target_email: Recipient email

        Returns:
            Dictionary of email headers
        """
        msg_id = f"<{uuid.uuid4()}@{sender_org.lower().replace(' ', '')}.com>"
        return {
            "From": f"{sender_org} <{sender_email}>",
            "To": target_email,
            "Reply-To": sender_email,
            "Message-ID": msg_id,
            "X-Mailer": f"{sender_org} Mail System",
            "MIME-Version": "1.0",
            "Content-Type": "multipart/alternative",
            "Date": datetime.now().strftime("%a, %d %b %Y %H:%M:%S +0000"),
            "X-Priority": "1",  # High priority
            # Simulated - these would normally be validated by mail servers
            "X-SPF-Status": "simulated-pass",
            "X-DKIM-Status": "simulated-pass",
            "X-PhishGuard": "SIMULATION - NOT A REAL PHISHING EMAIL",
        }

    def _degrade_quality(self, content: str) -> str:
        """Degrade content quality for basic sophistication (typos, bad grammar)."""
        replacements = {
            "your account": "you're acount",
            "immediately": "imediately",
            "password": "pasword",
            "verify": "verifiy",
            "Dear": "dear",
            "unauthorized": "un-authorized",
            "security": "securityy",
            "click here": "CLICK HERE NOW!!!",
        }
        for old, new in replacements.items():
            content = content.replace(old, new, 1)
        return content

    def _enhance_quality(self, content: str, target_name: str,
                          org_name: str) -> str:
        """Enhance content quality for advanced sophistication."""
        # Add personalization markers
        content = content.replace(
            "Best regards",
            f"Best regards,\nWe value your continued trust in {org_name}"
        )
        return content

    # -------------------------------------------------------------------------
    # Email templates
    # -------------------------------------------------------------------------

    def _template_password_reset(self, target_name, target_email, sender_org):
        """Password reset phishing template."""
        subject = f"[Action Required] Password Reset for Your {sender_org} Account"
        sender_name = f"{sender_org} Security Team"
        sender_email = f"security@{sender_org.lower().replace(' ', '')}.com"

        body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">
        <div style="text-align: center; margin-bottom: 20px;">
            <h2 style="color: #333;">🔒 {html.escape(sender_org)} Security Alert</h2>
        </div>
        <p>Dear {html.escape(target_name)},</p>
        <p>We detected unusual sign-in activity on your {html.escape(sender_org)} account
        associated with <strong>{html.escape(target_email)}</strong>.</p>
        <p>For your security, your account has been temporarily limited. Please reset
        your password immediately to restore full access.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{{{phishing_link}}}}"
               style="background: #dc3545; color: white; padding: 12px 30px;
                      text-decoration: none; border-radius: 5px; font-weight: bold;">
                Reset Password Now
            </a>
        </div>
        <p style="color: #666; font-size: 12px;">
            If you did not request this change, please reset your password immediately
            as someone may have unauthorized access to your account.</p>
        <hr style="border: 1px solid #eee;">
        <p style="color: #999; font-size: 11px;">
            {html.escape(sender_org)} Security Team<br>
            This is an automated security notification.</p>
    </div>
</body>
</html>"""

        body_text = (
            f"Dear {target_name},\n\n"
            f"We detected unusual sign-in activity on your {sender_org} account "
            f"associated with {target_email}.\n\n"
            f"Please reset your password immediately: {{{{phishing_link}}}}\n\n"
            f"Best regards,\n{sender_org} Security Team"
        )

        return subject, body_html, body_text, sender_name, sender_email

    def _template_invoice(self, target_name, target_email, sender_org):
        """Invoice/payment phishing template."""
        inv_num = f"INV-{uuid.uuid4().hex[:8].upper()}"
        subject = f"Invoice #{inv_num} - Payment Due from {sender_org}"
        sender_name = f"{sender_org} Billing"
        sender_email = f"billing@{sender_org.lower().replace(' ', '')}.com"

        body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="border: 1px solid #ddd; padding: 20px; border-radius: 8px;">
        <h2 style="color: #2c3e50;">📄 Invoice Notification</h2>
        <p>Dear {html.escape(target_name)},</p>
        <p>Please find attached your invoice from {html.escape(sender_org)}:</p>
        <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
            <tr style="background: #f8f9fa;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Invoice #</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{inv_num}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Amount Due</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">$2,459.00</td>
            </tr>
            <tr style="background: #f8f9fa;">
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Due Date</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">Within 48 hours</td>
            </tr>
        </table>
        <div style="text-align: center; margin: 20px 0;">
            <a href="{{{{phishing_link}}}}"
               style="background: #28a745; color: white; padding: 12px 30px;
                      text-decoration: none; border-radius: 5px;">
                View & Pay Invoice
            </a>
        </div>
        <p style="color: #999; font-size: 11px;">{html.escape(sender_org)} Billing Department</p>
    </div>
</body>
</html>"""

        body_text = (
            f"Dear {target_name},\n\n"
            f"Invoice #{inv_num} from {sender_org}\n"
            f"Amount: $2,459.00 | Due: Within 48 hours\n\n"
            f"View invoice: {{{{phishing_link}}}}\n\n"
            f"Best regards,\n{sender_org} Billing"
        )

        return subject, body_html, body_text, sender_name, sender_email

    def _template_account_verification(self, target_name, target_email, sender_org):
        """Account verification phishing template."""
        subject = f"Verify Your {sender_org} Account - Action Required"
        sender_name = f"{sender_org} Account Services"
        sender_email = f"accounts@{sender_org.lower().replace(' ', '')}.com"

        body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 30px; border-radius: 8px; color: white; text-align: center;">
        <h2>✉️ Account Verification Required</h2>
    </div>
    <div style="padding: 20px; border: 1px solid #ddd; border-top: none;">
        <p>Hello {html.escape(target_name)},</p>
        <p>As part of our ongoing security measures, we need to verify your account
        information for <strong>{html.escape(target_email)}</strong>.</p>
        <p>Failure to verify your account within <strong>24 hours</strong> will result
        in temporary account suspension.</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{{{phishing_link}}}}"
               style="background: #667eea; color: white; padding: 12px 30px;
                      text-decoration: none; border-radius: 5px;">
                Verify My Account
            </a>
        </div>
        <p style="color: #666; font-size: 12px;">
            This verification is mandatory for all users as part of our updated
            security policy.</p>
    </div>
</body>
</html>"""

        body_text = (
            f"Hello {target_name},\n\n"
            f"We need to verify your {sender_org} account ({target_email}).\n\n"
            f"Verify here: {{{{phishing_link}}}}\n\n"
            f"{sender_org} Account Services"
        )

        return subject, body_html, body_text, sender_name, sender_email

    def _template_prize_winner(self, target_name, target_email, sender_org):
        """Prize winner phishing template."""
        subject = f"🎉 Congratulations {target_name}! You've Won!"
        sender_name = f"{sender_org} Rewards Program"
        sender_email = f"rewards@{sender_org.lower().replace(' ', '')}.com"

        body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #ffd700; padding: 30px; text-align: center; border-radius: 8px;">
        <h1 style="color: #333;">🎉 YOU'RE A WINNER! 🎉</h1>
        <p style="font-size: 18px; color: #555;">Congratulations, {html.escape(target_name)}!</p>
    </div>
    <div style="padding: 20px;">
        <p>Dear {html.escape(target_name)},</p>
        <p>You have been selected as the winner of our {html.escape(sender_org)} Annual
        Loyalty Reward! You've won a <strong>$500 Gift Card</strong>!</p>
        <p>To claim your prize, simply verify your identity:</p>
        <div style="text-align: center; margin: 20px 0;">
            <a href="{{{{phishing_link}}}}"
               style="background: #ff6600; color: white; padding: 15px 40px;
                      text-decoration: none; border-radius: 5px; font-size: 18px;">
                🎁 Claim Your Prize
            </a>
        </div>
        <p style="color: #cc0000;"><strong>⏰ Offer expires in 12 hours!</strong></p>
    </div>
</body>
</html>"""

        body_text = (
            f"Congratulations {target_name}!\n\n"
            f"You've won a $500 Gift Card from {sender_org}!\n"
            f"Claim here: {{{{phishing_link}}}}\n\n"
            f"Offer expires in 12 hours!"
        )

        return subject, body_html, body_text, sender_name, sender_email

    def _template_it_support(self, target_name, target_email, sender_org):
        """IT support phishing template."""
        ticket = f"TKT-{uuid.uuid4().hex[:6].upper()}"
        subject = f"[{sender_org} IT] System Update Required - Ticket #{ticket}"
        sender_name = f"{sender_org} IT Department"
        sender_email = f"it-support@{sender_org.lower().replace(' ', '')}.com"

        body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #343a40; color: white; padding: 15px 20px; border-radius: 8px 8px 0 0;">
        <h3>🖥️ {html.escape(sender_org)} IT Support - Ticket #{ticket}</h3>
    </div>
    <div style="border: 1px solid #ddd; border-top: none; padding: 20px;">
        <p>Hi {html.escape(target_name)},</p>
        <p>Our IT team has detected that your workstation requires a mandatory
        security update. This update patches a critical vulnerability
        (CVE-2026-XXXX) affecting all employees.</p>
        <p><strong>Action Required:</strong> Please log in to the IT portal and
        install the update before end of business today.</p>
        <div style="text-align: center; margin: 25px 0;">
            <a href="{{{{phishing_link}}}}"
               style="background: #007bff; color: white; padding: 12px 30px;
                      text-decoration: none; border-radius: 5px;">
                Access IT Portal
            </a>
        </div>
        <p style="color: #666;">Failure to update may result in network access
        being revoked for your device.</p>
        <p>Best regards,<br>{html.escape(sender_org)} IT Support Team</p>
    </div>
</body>
</html>"""

        body_text = (
            f"Hi {target_name},\n\n"
            f"IT Ticket #{ticket}: Mandatory security update required.\n"
            f"Access the IT portal: {{{{phishing_link}}}}\n\n"
            f"{sender_org} IT Support"
        )

        return subject, body_html, body_text, sender_name, sender_email

    def _template_ceo_fraud(self, target_name, target_email, sender_org):
        """CEO fraud / Business Email Compromise template."""
        subject = f"Urgent Request - {target_name}, please handle confidentially"
        sender_name = f"CEO - {sender_org}"
        sender_email = f"ceo@{sender_org.lower().replace(' ', '')}.com"

        body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <p>Hi {html.escape(target_name)},</p>
    <p>I need you to handle something urgently and confidentially. I'm currently
    in a meeting and can't take calls.</p>
    <p>We need to process a wire transfer for a new vendor before end of day.
    Can you please review the details and authorize the payment?</p>
    <div style="text-align: center; margin: 25px 0;">
        <a href="{{{{phishing_link}}}}"
           style="background: #17a2b8; color: white; padding: 12px 30px;
                  text-decoration: none; border-radius: 5px;">
            Review Payment Details
        </a>
    </div>
    <p>Please keep this between us for now. I'll explain more when I'm out
    of this meeting.</p>
    <p>Thanks,<br><em>Sent from my iPhone</em></p>
</body>
</html>"""

        body_text = (
            f"Hi {target_name},\n\n"
            f"I need you to handle something urgently. Review and authorize "
            f"a vendor payment: {{{{phishing_link}}}}\n\n"
            f"Keep this confidential.\n\nSent from my iPhone"
        )

        return subject, body_html, body_text, sender_name, sender_email

    def _template_delivery_notification(self, target_name, target_email, sender_org):
        """Delivery notification phishing template."""
        tracking = f"PKG-{uuid.uuid4().hex[:10].upper()}"
        subject = f"📦 Your {sender_org} Package Delivery Update - {tracking}"
        sender_name = f"{sender_org} Delivery"
        sender_email = f"delivery@{sender_org.lower().replace(' ', '')}.com"

        body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #8B4513; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
        <h2>📦 Delivery Update</h2>
    </div>
    <div style="border: 1px solid #ddd; padding: 20px;">
        <p>Dear {html.escape(target_name)},</p>
        <p>We attempted to deliver your package but were unable to complete
        the delivery. Your package is being held at our distribution center.</p>
        <table style="width: 100%; margin: 15px 0;">
            <tr>
                <td><strong>Tracking #:</strong></td>
                <td>{tracking}</td>
            </tr>
            <tr>
                <td><strong>Status:</strong></td>
                <td style="color: orange;">⚠️ Delivery Failed - Action Required</td>
            </tr>
        </table>
        <p>Please confirm your delivery address to reschedule:</p>
        <div style="text-align: center; margin: 20px 0;">
            <a href="{{{{phishing_link}}}}"
               style="background: #8B4513; color: white; padding: 12px 30px;
                      text-decoration: none; border-radius: 5px;">
                Reschedule Delivery
            </a>
        </div>
    </div>
</body>
</html>"""

        body_text = (
            f"Dear {target_name},\n\n"
            f"Delivery failed for package {tracking}.\n"
            f"Reschedule: {{{{phishing_link}}}}\n\n"
            f"{sender_org} Delivery"
        )

        return subject, body_html, body_text, sender_name, sender_email

    def _template_social_media(self, target_name, target_email, sender_org):
        """Social media notification phishing template."""
        subject = f"⚠️ {sender_org}: Unusual Login Detected on Your Account"
        sender_name = f"{sender_org} Security"
        sender_email = f"no-reply@{sender_org.lower().replace(' ', '')}.com"

        body_html = f"""<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #1da1f2; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
        <h2>🔐 Security Alert</h2>
    </div>
    <div style="border: 1px solid #ddd; padding: 20px;">
        <p>Hi {html.escape(target_name)},</p>
        <p>We noticed a login to your {html.escape(sender_org)} account from a new
        device:</p>
        <div style="background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;">
            <p><strong>Device:</strong> Unknown Android Device</p>
            <p><strong>Location:</strong> Moscow, Russia</p>
            <p><strong>Time:</strong> {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
        </div>
        <p><strong>If this wasn't you</strong>, secure your account immediately:</p>
        <div style="text-align: center; margin: 20px 0;">
            <a href="{{{{phishing_link}}}}"
               style="background: #1da1f2; color: white; padding: 12px 30px;
                      text-decoration: none; border-radius: 5px;">
                Secure My Account
            </a>
        </div>
    </div>
</body>
</html>"""

        body_text = (
            f"Hi {target_name},\n\n"
            f"Unusual login detected on your {sender_org} account from Moscow, Russia.\n"
            f"Secure your account: {{{{phishing_link}}}}\n\n"
            f"{sender_org} Security"
        )

        return subject, body_html, body_text, sender_name, sender_email


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def generate_sample_emails(count: int = 5) -> List[PhishingEmail]:
    """Generate a set of sample phishing emails for demonstration."""
    generator = PhishingEmailGenerator()
    templates = generator.get_available_templates()
    samples = []

    targets = [
        ("John Smith", "john.smith@example.com"),
        ("Alice Johnson", "alice.j@example.com"),
        ("Bob Williams", "bob.w@example.com"),
        ("Carol Davis", "carol.d@example.com"),
        ("David Brown", "david.b@example.com"),
    ]

    for i in range(min(count, len(targets))):
        name, email = targets[i]
        template = templates[i % len(templates)]
        sophistication = ["basic", "intermediate", "advanced"][i % 3]

        phishing_email = generator.generate_email(
            template_type=template,
            target_name=name,
            target_email=email,
            sender_org="SecureCorp",
            sophistication=sophistication,
        )
        samples.append(phishing_email)

    return samples
