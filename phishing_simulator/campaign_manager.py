"""
Campaign Manager Module
=======================
Manages phishing simulation campaigns including creation, execution,
tracking, and reporting.

Uses SQLite for persistent storage of campaigns, targets, and interactions.
"""

import uuid
import json
import csv
import io
import sqlite3
import os
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple

from .config import Config


@dataclass
class Target:
    """A target for a phishing campaign."""
    target_id: str
    name: str
    email: str
    department: str = "General"


@dataclass
class Interaction:
    """A tracked interaction with a phishing email."""
    interaction_id: str
    campaign_id: str
    target_id: str
    action: str         # email_sent, email_opened, link_clicked, credentials_submitted, reported_phishing
    timestamp: str
    details: Optional[str] = None


@dataclass
class CampaignStats:
    """Statistics for a campaign."""
    total_targets: int = 0
    emails_sent: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    credentials_submitted: int = 0
    reported_phishing: int = 0

    @property
    def open_rate(self) -> float:
        return self.emails_opened / max(self.emails_sent, 1) * 100

    @property
    def click_rate(self) -> float:
        return self.links_clicked / max(self.emails_sent, 1) * 100

    @property
    def submission_rate(self) -> float:
        return self.credentials_submitted / max(self.emails_sent, 1) * 100

    @property
    def report_rate(self) -> float:
        return self.reported_phishing / max(self.emails_sent, 1) * 100

    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100). Higher = more vulnerable."""
        if self.emails_sent == 0:
            return 0.0
        # Weighted score: submissions matter most, reporting reduces score
        score = (
            (self.submission_rate * 0.5) +
            (self.click_rate * 0.3) +
            (self.open_rate * 0.1) -
            (self.report_rate * 0.2)
        )
        return max(0.0, min(100.0, score))


@dataclass
class Campaign:
    """A phishing simulation campaign."""
    campaign_id: str
    name: str
    template_type: str
    sophistication: str = "intermediate"
    status: str = "created"     # created, launched, completed
    created_at: str = ""
    launched_at: Optional[str] = None
    completed_at: Optional[str] = None
    targets: List[Target] = field(default_factory=list)
    stats: Optional[CampaignStats] = None


class CampaignManager:
    """
    Manages phishing simulation campaigns.

    Handles the complete lifecycle: creation, launching, interaction
    tracking, and report generation.

    Usage:
        manager = CampaignManager()
        campaign_id = manager.create_campaign(
            name="Q4 Security Test",
            template_type="password_reset",
            targets=[{"name": "John", "email": "john@co.com"}],
        )
        manager.launch_campaign(campaign_id)
        stats = manager.get_campaign_stats(campaign_id)
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or Config.DATABASE_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database with required tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS campaigns (
                campaign_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                template_type TEXT NOT NULL,
                sophistication TEXT DEFAULT 'intermediate',
                status TEXT DEFAULT 'created',
                created_at TEXT NOT NULL,
                launched_at TEXT,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS targets (
                target_id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                department TEXT DEFAULT 'General',
                FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id)
            );

            CREATE TABLE IF NOT EXISTS interactions (
                interaction_id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id),
                FOREIGN KEY (target_id) REFERENCES targets(target_id)
            );
        """)

        conn.commit()
        conn.close()

    def create_campaign(
        self,
        name: str,
        template_type: str,
        targets: List[Dict],
        sophistication: str = "intermediate",
        schedule: Optional[str] = None,
    ) -> str:
        """
        Create a new phishing simulation campaign.

        Args:
            name: Campaign name
            template_type: Type of phishing template
            targets: List of dicts with 'name', 'email', optional 'department'
            sophistication: basic/intermediate/advanced
            schedule: Optional schedule (not implemented in demo)

        Returns:
            campaign_id string
        """
        campaign_id = str(uuid.uuid4())[:8]
        now = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Insert campaign
        cursor.execute(
            "INSERT INTO campaigns (campaign_id, name, template_type, "
            "sophistication, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (campaign_id, name, template_type, sophistication, "created", now)
        )

        # Insert targets
        for t in targets:
            target_id = str(uuid.uuid4())[:8]
            cursor.execute(
                "INSERT INTO targets (target_id, campaign_id, name, email, department) "
                "VALUES (?, ?, ?, ?, ?)",
                (target_id, campaign_id, t["name"], t["email"],
                 t.get("department", "General"))
            )

        conn.commit()
        conn.close()

        return campaign_id

    def launch_campaign(self, campaign_id: str) -> Dict:
        """
        Launch a campaign (simulate sending phishing emails).

        In a real system, this would send actual emails. In this simulation,
        it marks emails as sent and generates simulated interactions.

        Args:
            campaign_id: ID of the campaign to launch

        Returns:
            Dict with launch status and details
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get campaign
        cursor.execute("SELECT * FROM campaigns WHERE campaign_id = ?",
                        (campaign_id,))
        campaign = cursor.fetchone()
        if not campaign:
            conn.close()
            raise ValueError(f"Campaign not found: {campaign_id}")

        if campaign[4] == "launched":
            conn.close()
            return {"status": "already_launched", "campaign_id": campaign_id}

        now = datetime.now().isoformat()

        # Update campaign status
        cursor.execute(
            "UPDATE campaigns SET status = 'launched', launched_at = ? "
            "WHERE campaign_id = ?",
            (now, campaign_id)
        )

        # Get targets
        cursor.execute("SELECT target_id FROM targets WHERE campaign_id = ?",
                        (campaign_id,))
        target_ids = [row[0] for row in cursor.fetchall()]

        # Record 'email_sent' for each target
        sent_count = 0
        for target_id in target_ids:
            interaction_id = str(uuid.uuid4())[:8]
            cursor.execute(
                "INSERT INTO interactions (interaction_id, campaign_id, "
                "target_id, action, timestamp) VALUES (?, ?, ?, ?, ?)",
                (interaction_id, campaign_id, target_id, "email_sent", now)
            )
            sent_count += 1

        # Simulate some interactions for demonstration
        import random
        random.seed(hash(campaign_id))

        for target_id in target_ids:
            # ~60% open the email
            if random.random() < 0.6:
                self._add_interaction(cursor, campaign_id, target_id,
                                       "email_opened", now)

                # ~40% of openers click the link
                if random.random() < 0.4:
                    self._add_interaction(cursor, campaign_id, target_id,
                                           "link_clicked", now)

                    # ~30% of clickers submit credentials
                    if random.random() < 0.3:
                        self._add_interaction(cursor, campaign_id, target_id,
                                               "credentials_submitted", now)

            # ~15% report as phishing
            if random.random() < 0.15:
                self._add_interaction(cursor, campaign_id, target_id,
                                       "reported_phishing", now)

        conn.commit()
        conn.close()

        return {
            "status": "launched",
            "campaign_id": campaign_id,
            "emails_sent": sent_count,
        }

    def track_interaction(self, campaign_id: str, target_id: str,
                           action: str, details: str = "") -> str:
        """
        Track a user interaction with a phishing email.

        Args:
            campaign_id: Campaign identifier
            target_id: Target identifier
            action: Type of interaction
            details: Additional details

        Returns:
            interaction_id
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        interaction_id = str(uuid.uuid4())[:8]
        now = datetime.now().isoformat()

        cursor.execute(
            "INSERT INTO interactions (interaction_id, campaign_id, "
            "target_id, action, timestamp, details) VALUES (?, ?, ?, ?, ?, ?)",
            (interaction_id, campaign_id, target_id, action, now, details)
        )

        conn.commit()
        conn.close()
        return interaction_id

    def get_campaign_stats(self, campaign_id: str) -> CampaignStats:
        """Get statistics for a campaign."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Count targets
        cursor.execute("SELECT COUNT(*) FROM targets WHERE campaign_id = ?",
                        (campaign_id,))
        total_targets = cursor.fetchone()[0]

        # Count interactions by type
        actions = ["email_sent", "email_opened", "link_clicked",
                    "credentials_submitted", "reported_phishing"]
        counts = {}
        for action in actions:
            cursor.execute(
                "SELECT COUNT(DISTINCT target_id) FROM interactions "
                "WHERE campaign_id = ? AND action = ?",
                (campaign_id, action)
            )
            counts[action] = cursor.fetchone()[0]

        conn.close()

        return CampaignStats(
            total_targets=total_targets,
            emails_sent=counts.get("email_sent", 0),
            emails_opened=counts.get("email_opened", 0),
            links_clicked=counts.get("link_clicked", 0),
            credentials_submitted=counts.get("credentials_submitted", 0),
            reported_phishing=counts.get("reported_phishing", 0),
        )

    def get_all_campaigns(self) -> List[Dict]:
        """Get all campaigns with their stats."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM campaigns ORDER BY created_at DESC")
        campaigns = cursor.fetchall()
        conn.close()

        result = []
        for c in campaigns:
            stats = self.get_campaign_stats(c[0])
            result.append({
                "campaign_id": c[0],
                "name": c[1],
                "template_type": c[2],
                "sophistication": c[3],
                "status": c[4],
                "created_at": c[5],
                "launched_at": c[6],
                "completed_at": c[7],
                "stats": {
                    "total_targets": stats.total_targets,
                    "emails_sent": stats.emails_sent,
                    "open_rate": round(stats.open_rate, 1),
                    "click_rate": round(stats.click_rate, 1),
                    "submission_rate": round(stats.submission_rate, 1),
                    "report_rate": round(stats.report_rate, 1),
                    "risk_score": round(stats.risk_score, 1),
                },
            })

        return result

    def export_report(self, campaign_id: str, fmt: str = "json") -> str:
        """
        Export campaign report.

        Args:
            campaign_id: Campaign to export
            fmt: Export format ('json' or 'csv')

        Returns:
            Report content as string
        """
        stats = self.get_campaign_stats(campaign_id)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get campaign info
        cursor.execute("SELECT * FROM campaigns WHERE campaign_id = ?",
                        (campaign_id,))
        campaign = cursor.fetchone()

        # Get all interactions
        cursor.execute(
            "SELECT i.*, t.name, t.email, t.department "
            "FROM interactions i JOIN targets t ON i.target_id = t.target_id "
            "WHERE i.campaign_id = ? ORDER BY i.timestamp",
            (campaign_id,)
        )
        interactions = cursor.fetchall()
        conn.close()

        if fmt == "json":
            report = {
                "campaign": {
                    "id": campaign[0] if campaign else campaign_id,
                    "name": campaign[1] if campaign else "Unknown",
                    "template_type": campaign[2] if campaign else "",
                    "sophistication": campaign[3] if campaign else "",
                    "status": campaign[4] if campaign else "",
                },
                "stats": {
                    "total_targets": stats.total_targets,
                    "emails_sent": stats.emails_sent,
                    "emails_opened": stats.emails_opened,
                    "links_clicked": stats.links_clicked,
                    "credentials_submitted": stats.credentials_submitted,
                    "reported_phishing": stats.reported_phishing,
                    "open_rate": round(stats.open_rate, 1),
                    "click_rate": round(stats.click_rate, 1),
                    "submission_rate": round(stats.submission_rate, 1),
                    "report_rate": round(stats.report_rate, 1),
                    "risk_score": round(stats.risk_score, 1),
                },
                "interactions": [
                    {
                        "target_name": i[6],
                        "target_email": i[7],
                        "department": i[8],
                        "action": i[3],
                        "timestamp": i[4],
                    }
                    for i in interactions
                ],
                "generated_at": datetime.now().isoformat(),
            }
            return json.dumps(report, indent=2)

        elif fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Target Name", "Email", "Department",
                              "Action", "Timestamp"])
            for i in interactions:
                writer.writerow([i[6], i[7], i[8], i[3], i[4]])
            return output.getvalue()

        else:
            raise ValueError(f"Unsupported format: {fmt}")

    def get_department_risk_scores(self, campaign_id: str) -> Dict[str, float]:
        """Calculate risk scores grouped by department."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT t.department, i.action, COUNT(DISTINCT t.target_id) "
            "FROM targets t LEFT JOIN interactions i "
            "ON t.target_id = i.target_id AND t.campaign_id = i.campaign_id "
            "WHERE t.campaign_id = ? GROUP BY t.department, i.action",
            (campaign_id,)
        )
        rows = cursor.fetchall()
        conn.close()

        dept_data = {}
        for dept, action, count in rows:
            if dept not in dept_data:
                dept_data[dept] = {}
            if action:
                dept_data[dept][action] = count

        risk_scores = {}
        for dept, actions in dept_data.items():
            sent = actions.get("email_sent", 1)
            clicked = actions.get("link_clicked", 0)
            submitted = actions.get("credentials_submitted", 0)
            reported = actions.get("reported_phishing", 0)

            score = ((submitted / sent * 50) + (clicked / sent * 30) -
                      (reported / sent * 20))
            risk_scores[dept] = max(0.0, min(100.0, score * 100))

        return risk_scores

    def _add_interaction(self, cursor, campaign_id, target_id, action, timestamp):
        """Helper to add an interaction record."""
        interaction_id = str(uuid.uuid4())[:8]
        cursor.execute(
            "INSERT INTO interactions (interaction_id, campaign_id, "
            "target_id, action, timestamp) VALUES (?, ?, ?, ?, ?)",
            (interaction_id, campaign_id, target_id, action, timestamp)
        )
