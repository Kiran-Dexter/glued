#!/usr/bin/env python3
import os
import smtplib
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def send_email(to_addr, subject, content, attachment_path=None):
    from_addr   = os.environ.get("EMAIL_FROM", "your_email@gmail.com")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port   = int(os.environ.get("SMTP_PORT", "587"))
    username    = os.environ.get("EMAIL_USERNAME", "your_email@gmail.com")
    password    = os.environ.get("EMAIL_PASSWORD", "your_password")

    msg = MIMEMultipart()
    msg['From']    = from_addr
    msg['To']      = to_addr
    msg['Subject'] = subject

    msg.attach(MIMEText(content, 'plain'))

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
            print("Attachment file does not exist. Skipping attachment.")

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Upgrade to a secure connection
            server.login(username, password)
            server.send_message(msg)
            print("Email sent successfully!")
    except Exception as e:
        print("Error sending email:", e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Send an email with optional attachment via Gmail SMTP")
    parser.add_argument("--to", required=True, help="Recipient email address")
    parser.add_argument("--subject", required=True, help="Email subject")
    parser.add_argument("--content", required=True, help="Email content (plain text)")
    parser.add_argument("--attachment", required=False, default=None, help="Optional file attachment path")

    args = parser.parse_args()

    send_email(args.to, args.subject, args.content, args.attachment)
