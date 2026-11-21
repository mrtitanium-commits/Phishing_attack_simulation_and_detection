"""
Dashboard Module
================
Flask-based Web Application for the PhishGuard Framework.
Provides visual monitoring of phishing campaigns, live heuristic analysis,
awareness training quizzes, and security reporting.
"""

import os
import io
from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, flash, send_file, Response
)

from .config import Config, get_config
from .campaign_manager import CampaignManager
from .url_analyzer import URLAnalyzer
from .email_analyzer import EmailAnalyzer
from .awareness_trainer import AwarenessTrainer


def create_app(config=None):
    """Factory function to build and configure the Flask web dashboard."""
    app = Flask(
        __name__,
        template_folder=Config.TEMPLATE_DIR,
        static_folder=os.path.join(Config.PACKAGE_DIR, "static")
    )

    if config is None:
        config = get_config()

    app.config.from_object(config)
    app.secret_key = config.SECRET_KEY

    campaign_mgr = CampaignManager(db_path=config.DATABASE_PATH)
    url_analyzer = URLAnalyzer()
    email_analyzer = EmailAnalyzer()
    trainer = AwarenessTrainer(quiz_file=config.QUIZ_FILE)

    # -------------------------------------------------------------------------
    # Overview / Dashboard
    # -------------------------------------------------------------------------

    @app.route("/")
    def dashboard():
        campaigns = campaign_mgr.get_all_campaigns()
        total_campaigns = len(campaigns)
        total_emails = sum(c["stats"]["emails_sent"] for c in campaigns)

        avg_clicks = (
            sum(c["stats"]["click_rate"] for c in campaigns) / total_campaigns
            if total_campaigns > 0 else 0.0
        )
        avg_reports = (
            sum(c["stats"]["report_rate"] for c in campaigns) / total_campaigns
            if total_campaigns > 0 else 0.0
        )

        return render_template(
            "html/dashboard.html",
            campaigns=campaigns,
            total_campaigns=total_campaigns,
            total_emails_sent=total_emails,
            avg_click_rate=round(avg_clicks, 1),
            avg_report_rate=round(avg_reports, 1)
        )

    # -------------------------------------------------------------------------
    # Campaign Management
    # -------------------------------------------------------------------------

    @app.route("/campaigns")
    def campaigns():
        all_campaigns = campaign_mgr.get_all_campaigns()
        return render_template("html/campaigns.html", campaigns=all_campaigns)

    @app.route("/campaigns/create", methods=["POST"])
    def create_campaign_route():
        name = request.form.get("name", "Untitled Campaign").strip()
        template_type = request.form.get("template_type", "password_reset")
        sophistication = request.form.get("sophistication", "intermediate")
        targets_raw = request.form.get("targets", "").strip()

        target_list = []
        for line in targets_raw.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                target_list.append({
                    "name": parts[0],
                    "email": parts[1],
                    "department": parts[2] if len(parts) > 2 else "General"
                })

        if not target_list:
            flash("Please provide at least one valid target (Name, Email).", "warning")
            return redirect(url_for("campaigns"))

        c_id = campaign_mgr.create_campaign(
            name=name,
            template_type=template_type,
            targets=target_list,
            sophistication=sophistication
        )
        flash(f"Campaign '{name}' created successfully (ID: {c_id}).", "success")
        return redirect(url_for("campaigns"))

    @app.route("/campaigns/<campaign_id>/launch", methods=["POST"])
    def launch_campaign_route(campaign_id):
        try:
            res = campaign_mgr.launch_campaign(campaign_id)
            flash(f"Simulation campaign launched! Sent {res.get('emails_sent', 0)} simulated phishing emails.", "success")
        except Exception as e:
            flash(f"Launch failed: {e}", "danger")
        return redirect(url_for("campaigns"))

    @app.route("/campaigns/<campaign_id>")
    def campaign_detail_route(campaign_id):
        stats = campaign_mgr.get_campaign_stats(campaign_id)
        dept_scores = campaign_mgr.get_department_risk_scores(campaign_id)
        return render_template(
            "html/reports.html",
            campaigns=campaign_mgr.get_all_campaigns(),
            focused_stats=stats,
            dept_scores=dept_scores
        )

    # -------------------------------------------------------------------------
    # Detection & Analysis Engine
    # -------------------------------------------------------------------------

    @app.route("/analyze")
    def analyze_page():
        return render_template("html/analyze.html")

    @app.route("/analyze/url", methods=["POST"])
    def analyze_url_route():
        data = request.get_json() or {}
        target_url = data.get("url", "")
        if not target_url:
            return jsonify({"error": "No URL provided"}), 400

        result = url_analyzer.analyze_url(target_url)
        return jsonify({
            "url": result.url,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "has_ssl": result.has_ssl,
            "is_shortened": result.is_shortened,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "details": f.details
                }
                for f in result.findings
            ]
        })

    @app.route("/analyze/email", methods=["POST"])
    def analyze_email_route():
        data = request.get_json() or {}
        subject = data.get("subject", "")
        sender = data.get("sender", "")
        body = data.get("body", "")

        result = email_analyzer.analyze_email(
            subject=subject,
            body=body,
            sender=sender
        )

        return jsonify({
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "recommended_action": result.recommended_action,
            "social_engineering_tactics": [
                {
                    "tactic": t.tactic,
                    "confidence": t.confidence,
                    "description": t.description
                }
                for t in result.social_engineering_tactics
            ],
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description
                }
                for f in result.findings
            ],
            "urls_found": result.urls_found
        })

    # -------------------------------------------------------------------------
    # Awareness Training & Quizzes
    # -------------------------------------------------------------------------

    @app.route("/training")
    def training_page():
        difficulty = request.args.get("difficulty", "beginner")
        questions = trainer.generate_quiz(difficulty=difficulty, count=5)
        topics = trainer.get_available_topics()
        return render_template(
            "html/training.html",
            questions=questions,
            topics=topics,
            difficulty=difficulty
        )

    @app.route("/training/submit", methods=["POST"])
    def submit_quiz():
        difficulty = request.form.get("difficulty", "beginner")
        user_responses = []

        for key, val in request.form.items():
            if key.startswith("answer_"):
                q_id = key.replace("answer_", "")
                user_responses.append({
                    "question_id": q_id,
                    "answer": int(val),
                    "difficulty": difficulty
                })

        report_card = trainer.generate_report_card(user_responses)
        flash(f"Assessment complete! You scored {report_card.score_percent}% ({report_card.correct_answers}/{report_card.total_questions} correct).", "info")
        return render_template(
            "html/training.html",
            questions=trainer.generate_quiz(difficulty=difficulty, count=5),
            topics=trainer.get_available_topics(),
            difficulty=difficulty,
            report_card=report_card
        )

    # -------------------------------------------------------------------------
    # Reports & Exports
    # -------------------------------------------------------------------------

    @app.route("/reports")
    def reports_page():
        all_campaigns = campaign_mgr.get_all_campaigns()
        return render_template("html/reports.html", campaigns=all_campaigns)

    @app.route("/reports/<campaign_id>/export/<fmt>")
    def export_report_route(campaign_id, fmt):
        try:
            content = campaign_mgr.export_report(campaign_id, fmt=fmt)
            mime = "application/json" if fmt == "json" else "text/csv"
            filename = f"phishguard_report_{campaign_id}.{fmt}"
            return Response(
                content,
                mimetype=mime,
                headers={"Content-Disposition": f"attachment;filename={filename}"}
            )
        except Exception as e:
            flash(f"Export error: {e}", "danger")
            return redirect(url_for("reports_page"))

    # -------------------------------------------------------------------------
    # Simulation Callbacks (Tracking & Landing Awareness Pages)
    # -------------------------------------------------------------------------

    @app.route("/track/<campaign_id>/<target_id>/open.png")
    def tracking_pixel(campaign_id, target_id):
        campaign_mgr.track_interaction(campaign_id, target_id, "email_opened")
        # Return 1x1 transparent GIF
        transparent_pixel = b'GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;'
        return send_file(io.BytesIO(transparent_pixel), mimetype="image/gif")

    @app.route("/landing/<campaign_id>/<target_id>")
    def landing_page(campaign_id, target_id):
        # Record that the link was clicked
        campaign_mgr.track_interaction(campaign_id, target_id, "link_clicked")
        
        # Educational awareness landing page
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Security Awareness Alert</title>
          <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
          <style>
            body {{ background-color: #0f172a; color: #f8fafc; font-family: system-ui, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }}
            .card {{ background-color: #1e293b; border: 1px solid #334155; border-radius: 12px; }}
          </style>
        </head>
        <body>
          <div class="container" style="max-width: 640px;">
            <div class="card p-5 shadow-lg text-center">
              <div class="display-3 mb-3">🛡️</div>
              <h2 class="text-warning fw-bold mb-3">Whoops! This Was a Phishing Simulation Drill</h2>
              <p class="text-light fs-5 mb-4">
                You clicked a simulated phishing link sent by your security team as part of our authorized security awareness program.
              </p>
              <div class="alert alert-dark text-start border-secondary mb-4">
                <h6 class="text-info fw-bold mb-2">Key Indicators You Missed:</h6>
                <ul class="mb-0 text-muted small">
                  <li>Artificial urgency ("Immediate Action Required", "Account Suspended in 2 hours")</li>
                  <li>Suspicious sender address and unverified domain name</li>
                  <li>Generic greetings and unprompted requests for credentials</li>
                </ul>
              </div>
              <p class="small text-muted mb-4">
                No credentials were compromised and your computer is safe. Please take 5 minutes to complete the awareness training.
              </p>
              <a href="/training" class="btn btn-primary btn-lg fw-semibold">Take Awareness Training</a>
            </div>
          </div>
        </body>
        </html>
        """

    @app.route("/api/stats")
    def api_stats():
        campaigns = campaign_mgr.get_all_campaigns()
        return jsonify({"campaigns": campaigns})

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
