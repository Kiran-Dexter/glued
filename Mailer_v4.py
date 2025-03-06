#!/usr/bin/env python3
import os
import smtplib
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Hardcoded SMTP configuration
FROM_ADDR   = "your_email@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT   = 587
USERNAME    = "your_email@gmail.com"
PASSWORD    = "your_password"

DEFAULT_CONTENT_FILE = "default_email.txt"

def get_default_content():
    """Read the default email content from a file."""
    if os.path.isfile(DEFAULT_CONTENT_FILE):
        try:
            with open(DEFAULT_CONTENT_FILE, "r") as file:
                return file.read()
        except Exception as e:
            print("Error reading default content file:", e)
            return ""
    else:
        print(f"Default content file '{DEFAULT_CONTENT_FILE}' not found. Continuing with empty default content.")
        return ""

def build_email_content(cli_content):
    """
    Build the final email content.
    If cli_content is provided, it is prepended to the default content.
    Otherwise, only the default content is used.
    """
    default_content = get_default_content()
    if cli_content:
        return cli_content + "\n\n" + default_content
    else:
        return default_content

def send_email(to_addr, subject, cli_content, attachment_path=None):
    # Build the final email content
    content = build_email_content(cli_content)

    msg = MIMEMultipart()
    msg['From']    = FROM_ADDR
    msg['To']      = to_addr
    msg['Subject'] = subject

    msg.attach(MIMEText(content, 'plain'))

    # Check if attachment is provided and valid; if not, just skip it.
    if attachment_path:
        if os.path.isfile(attachment_path):
            try:
                with open(attachment_path, "rb") as attachment_file:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment_file.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(attachment_path)}"')
                msg.attach(part)
            except Exception as e:
                print("Error attaching file:", e)
        else:
            print("Attachment file does not exist. Sending email without attachment.")

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Upgrade to a secure connection
            server.login(USERNAME, PASSWORD)
            server.send_message(msg)
            print("Email sent successfully!")
    except Exception as e:
        print("Error sending email:", e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Send an email with optional attachment via Gmail SMTP")
    parser.add_argument("--to", required=True, help="Recipient email address")
    parser.add_argument("--subject", required=True, help="Email subject")
    parser.add_argument("--content", required=False, default="", help="Optional custom message to prepend to the default content")
    parser.add_argument("--attachment", required=False, default=None, help="Optional file attachment path")

    args = parser.parse_args()

    send_email(args.to, args.subject, args.content, args.attachment)
