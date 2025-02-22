# src/utils/notifications.py
import smtplib
from email.mime.text import MIMEText

def send_notifications(report):
    msg = MIMEText(f"Security Scan Report:\n{report}")
    msg['Subject'] = "Security Report"
    msg['From'] = "gathekanav@gmail.com"
    msg['To'] = "gathekanav@gmail.com"
    with smtplib.SMTP("smtp.company.com", 587) as server:
        server.starttls()
        server.send_message(msg)
    print("Notification sent.")