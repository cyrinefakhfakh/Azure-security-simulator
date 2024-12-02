from app import app, db
from app import SecurityAlert, Recommendation, ComplianceStatus, User, SecurityEvent
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash

def add_data():
    with app.app_context():
        # Add Users
        users = [
            User(
                username="Ahmed",
                email="Ahmed@example.com",
                password_hash=generate_password_hash("user1password"),
                totp_secret="JBSWY3DPEHPK3PXP"
            ),
            User(
                username="Ali",
                email="Ali@example.com",
                password_hash=generate_password_hash("user2password"),
                totp_secret="JBSWY3DPEHPK3PXP"
            ),
            User(
                username="Amani",
                email="Amani@example.com",
                password_hash=generate_password_hash("user3password"),
                totp_secret="JBSWY3DPEHPK3PXP"
            ),
            User(
                username="Rana",
                email="rana@example.com",
                password_hash=generate_password_hash("user4password"),
                totp_secret="JBSWY3DPEHPK3PXP"
            ),
            User(
                username="Yosser",
                email="Yosser@example.com",
                password_hash=generate_password_hash("user5password"),
                totp_secret="JBSWY3DPEHPK3PXP"
            ),
            User(
                username="Wafa",
                email="Wafa@example.com",
                password_hash=generate_password_hash("user6password"),
                totp_secret="JBSWY3DPEHPK3PXP"
            ),
            
        ]
        db.session.bulk_save_objects(users)

        # Add Security Alerts
        alerts = [
            SecurityAlert(
                title="Unauthorized Access Attempt",
                description="An unauthorized access attempt was detected.",
                severity="High",
                status="Unresolved",
                timestamp=datetime.utcnow() - timedelta(days=1)
            ),
            SecurityAlert(
                title="Malware Detected",
                description="Malware was detected on the server.",
                severity="Medium",
                status="Resolved",
                timestamp=datetime.utcnow() - timedelta(days=2)
            ),
            SecurityAlert(
                title="Suspicious Activity",
                description="Suspicious activity was detected in the network.",
                severity="Low",
                status="Unresolved",
                timestamp=datetime.utcnow() - timedelta(days=3)
            ),
            SecurityAlert(
                title="Phishing Attempt",
                description="A phishing attempt was detected.",
                severity="High",
                status="Unresolved",
                timestamp=datetime.utcnow() - timedelta(days=4)
            ),
            SecurityAlert(
                title="DDoS Attack",
                description="A DDoS attack was detected.",
                severity="High",
                status="Resolved",
                timestamp=datetime.utcnow() - timedelta(days=5)
            ),
            SecurityAlert(
                title="Data Breach",
                description="A data breach was detected.",
                severity="High",
                status="Unresolved",
                timestamp=datetime.utcnow() - timedelta(days=6)
            ),
            SecurityAlert(
                title="Ransomware Detected",
                description="Ransomware was detected on the server.",
                severity="High",
                status="Resolved",
                timestamp=datetime.utcnow() - timedelta(days=7)
            ),
            SecurityAlert(
                title="Unauthorized Access Attempt",
                description="An unauthorized access attempt was detected.",
                severity="High",
                status="Unresolved",
                timestamp=datetime.utcnow() - timedelta(days=8)
            ),
            SecurityAlert(
                title="Malware Detected",
                description="Malware was detected on the server.",
                severity="Medium",
                status="Resolved",
                timestamp=datetime.utcnow() - timedelta(days=9)
            ),
            SecurityAlert(
                title="Suspicious Activity",
                description="Suspicious activity was detected in the network.",
                severity="Low",
                status="Unresolved",
                timestamp=datetime.utcnow() - timedelta(days=10)
            )
        ]
        db.session.bulk_save_objects(alerts)

        # Add Recommendations
        recommendations = [
            Recommendation(
                title="Update Antivirus Software",
                description="Ensure that the antivirus software is up to date.",
                status="Pending"
            ),
            Recommendation(
                title="Enable Multi-Factor Authentication",
                description="Enable multi-factor authentication for all users.",
                status="Implemented"
            ),
            Recommendation(
                title="Conduct Security Training",
                description="Conduct security training for all employees.",
                status="Pending"
            ),
            Recommendation(
                title="Implement Network Segmentation",
                description="Implement network segmentation to improve security.",
                status="Pending"
            ),
            Recommendation(
                title="Regularly Update Software",
                description="Ensure that all software is regularly updated.",
                status="Implemented"
            ),
            Recommendation(
                title="Perform Regular Backups",
                description="Perform regular backups of all critical data.",
                status="Pending"
            ),
            Recommendation(
                title="Monitor Network Traffic",
                description="Monitor network traffic for suspicious activity.",
                status="Pending"
            ),
            Recommendation(
                title="Use Strong Passwords",
                description="Ensure that all users use strong passwords.",
                status="Implemented"
            ),
            Recommendation(
                title="Enable Firewall",
                description="Enable firewall to protect the network.",
                status="Implemented"
            ),
            Recommendation(
                title="Review Access Controls",
                description="Review access controls to ensure they are up to date.",
                status="Pending"
            )
        ]
        db.session.bulk_save_objects(recommendations)

        # Add Compliance Statuses
        compliance_statuses = [
            ComplianceStatus(
                control="Access Control",
                status="Compliant",
                timestamp=datetime.utcnow() - timedelta(days=1)
            ),
            ComplianceStatus(
                control="Data Encryption",
                status="Non-Compliant",
                timestamp=datetime.utcnow() - timedelta(days=2)
            ),
            ComplianceStatus(
                control="Network Security",
                status="Compliant",
                timestamp=datetime.utcnow() - timedelta(days=3)
            ),
            ComplianceStatus(
                control="Incident Response",
                status="Non-Compliant",
                timestamp=datetime.utcnow() - timedelta(days=4)
            ),
            ComplianceStatus(
                control="Physical Security",
                status="Compliant",
                timestamp=datetime.utcnow() - timedelta(days=5)
            ),
            ComplianceStatus(
                control="Access Control",
                status="Compliant",
                timestamp=datetime.utcnow() - timedelta(days=6)
            ),
            ComplianceStatus(
                control="Data Encryption",
                status="Non-Compliant",
                timestamp=datetime.utcnow() - timedelta(days=7)
            ),
            ComplianceStatus(
                control="Network Security",
                status="Compliant",
                timestamp=datetime.utcnow() - timedelta(days=8)
            ),
            ComplianceStatus(
                control="Incident Response",
                status="Non-Compliant",
                timestamp=datetime.utcnow() - timedelta(days=9)
            ),
            ComplianceStatus(
                control="Physical Security",
                status="Compliant",
                timestamp=datetime.utcnow() - timedelta(days=10)
            )
        ]
        db.session.bulk_save_objects(compliance_statuses)

        # Add Security Events
        security_events = [
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=1),
                event_type="Login Attempt",
                severity="Info",
                description="User admin attempted to log in."
            ),
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=2),
                event_type="Password Change",
                severity="Warning",
                description="User user1 changed their password."
            ),
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=3),
                event_type="Failed Login",
                severity="High",
                description="Multiple failed login attempts detected for user2."
            ),
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=4),
                event_type="Login Attempt",
                severity="Info",
                description="User user3 attempted to log in."
            ),
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=5),
                event_type="Password Change",
                severity="Warning",
                description="User user4 changed their password."
            ),
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=6),
                event_type="Failed Login",
                severity="High",
                description="Multiple failed login attempts detected for user5."
            ),
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=7),
                event_type="Login Attempt",
                severity="Info",
                description="User user6 attempted to log in."
            ),
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=8),
                event_type="Password Change",
                severity="Warning",
                description="User user7 changed their password."
            ),
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=9),
                event_type="Failed Login",
                severity="High",
                description="Multiple failed login attempts detected for user8."
            ),
            SecurityEvent(
                timestamp=datetime.utcnow() - timedelta(days=10),
                event_type="Login Attempt",
                severity="Info",
                description="User user9 attempted to log in."
            ),
            SecurityEvent(event_type='Login Attempt', description='Failed login attempt from IP 192.168.1.1', severity='HIGH'),
            SecurityEvent(event_type='Password Change', description='User changed password', severity='MEDIUM'),
            SecurityEvent(event_type='File Upload', description='User uploaded a file', severity='LOW'),
            SecurityEvent(event_type='Login Attempt', description='Successful login from IP 192.168.1.2', severity='LOW'),
            SecurityEvent(event_type='Data Export', description='User exported data', severity='MEDIUM')
        ]
        db.session.bulk_save_objects(security_events)

        # Commit the changes
        db.session.commit()
        print("Data added successfully.")

if __name__ == "__main__":
    add_data()