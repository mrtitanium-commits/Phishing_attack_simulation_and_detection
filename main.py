#!/usr/bin/env python3
"""
PhishGuard - Main CLI Entrypoint
================================
Command-line interface for the Phishing Attack Simulation & Detection Framework.

Subcommands:
  dashboard       Launch the web UI dashboard
  analyze-url     Analyze a URL for phishing indicators
  analyze-email   Analyze an email for social engineering and phishing
  campaign        Manage simulation campaigns (create, launch, report)
  train-model     Train or retrain the ML phishing detection model
  quiz            Take an interactive cybersecurity awareness quiz
  demo            Execute an automated end-to-end demonstration
"""

import sys
import os
import argparse
import json
from pprint import pprint

# Optional colorama for colored CLI output
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    CYAN = Fore.CYAN
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    BRIGHT = Style.BRIGHT
    RESET = Style.RESET_ALL
except ImportError:
    CYAN = ""
    GREEN = ""
    YELLOW = ""
    RED = ""
    BRIGHT = ""
    RESET = ""

from phishing_simulator.config import Config, get_config
from phishing_simulator.email_generator import PhishingEmailGenerator
from phishing_simulator.campaign_manager import CampaignManager
from phishing_simulator.url_analyzer import URLAnalyzer
from phishing_simulator.website_analyzer import WebsiteAnalyzer
from phishing_simulator.email_analyzer import EmailAnalyzer
from phishing_simulator.ml_detector import PhishingMLDetector
from phishing_simulator.awareness_trainer import AwarenessTrainer


BANNER = rf"""{CYAN}{BRIGHT}
======================================================================
  ____  _     _     _      ____                     _ 
 |  _ \| |__ (_)___| |__  / ___|_   _  __ _ _ __ __| |
 | |_) | '_ \| / __| '_ \| |  _| | | |/ _` | '__/ _` |
 |  __/| | | | \__ \ | | | |_| | |_| | (_| | | | (_| |
 |_|   |_| |_|_|___/_| |_|\____|\__,_|\__,_|_|  \__,_|
 
  Phishing Attack Simulation & Detection Framework (v1.0.0)
  For Educational & Authorized Defensive Testing Only
======================================================================{RESET}
"""


def cmd_dashboard(args):
    """Launch the Flask web dashboard."""
    print(f"{GREEN}Starting PhishGuard Web Dashboard at http://{args.host}:{args.port}{RESET}")
    print(f"{YELLOW}Press Ctrl+C to terminate the dashboard server.{RESET}\n")
    from phishing_simulator.dashboard import create_app
    app = create_app()
    app.run(host=args.host, port=args.port, debug=args.debug)


def cmd_analyze_url(args):
    """Analyze a URL from CLI."""
    analyzer = URLAnalyzer()
    print(f"\n{CYAN}Inspecting URL:{RESET} {args.url}")
    result = analyzer.analyze_url(args.url)

    color = RED if result.risk_score >= 60 else (YELLOW if result.risk_score >= 30 else GREEN)
    print(f"\n{BRIGHT}Risk Assessment:{RESET} {color}{result.risk_level} (Score: {result.risk_score}/100){RESET}")
    print(f"SSL Encryption: {'Yes (HTTPS)' if result.has_ssl else 'No (HTTP)'}")
    print(f"URL Shortened:  {'Yes' if result.is_shortened else 'No'}")
    print(f"\n{BRIGHT}Findings ({len(result.findings)}):{RESET}")
    for f in result.findings:
        f_color = RED if f.severity in ['HIGH', 'CRITICAL'] else (YELLOW if f.severity == 'MEDIUM' else CYAN)
        print(f"  • [{f_color}{f.severity}{RESET}] {f.description}")
        if f.details:
            print(f"      Details: {f.details}")
    print()


def cmd_analyze_email(args):
    """Analyze email content for phishing indicators."""
    analyzer = EmailAnalyzer()
    print(f"\n{CYAN}Inspecting Email:{RESET}")
    print(f"  Sender:  {args.sender}")
    print(f"  Subject: {args.subject}\n")

    result = analyzer.analyze_email(
        subject=args.subject,
        body=args.body,
        sender=args.sender
    )

    color = RED if result.risk_score >= 60 else (YELLOW if result.risk_score >= 30 else GREEN)
    print(f"{BRIGHT}Risk Assessment:{RESET} {color}{result.risk_level} (Score: {result.risk_score}/100){RESET}")
    print(f"{BRIGHT}Recommended Action:{RESET} {result.recommended_action}\n")

    if result.social_engineering_tactics:
        print(f"{BRIGHT}Social Engineering Tactics Detected:{RESET}")
        for t in result.social_engineering_tactics:
            print(f"  • {YELLOW}{t.tactic.upper()}{RESET} (Confidence: {t.confidence:.0%})")
            print(f"      {t.description}")

    if result.findings:
        print(f"\n{BRIGHT}Key Findings:{RESET}")
        for f in result.findings:
            f_color = RED if f.severity in ['HIGH', 'CRITICAL'] else (YELLOW if f.severity == 'MEDIUM' else CYAN)
            print(f"  • [{f_color}{f.severity}{RESET}] {f.description}")
    print()


def cmd_campaign(args):
    """Handle campaign subcommands."""
    mgr = CampaignManager()
    if args.action == "create":
        targets = []
        if os.path.exists(args.targets):
            with open(args.targets, 'r') as f:
                for line in f:
                    parts = [p.strip() for p in line.split(',') if p.strip()]
                    if len(parts) >= 2:
                        targets.append({"name": parts[0], "email": parts[1], "department": parts[2] if len(parts) > 2 else "General"})
        else:
            targets = [{"name": "Sample Target", "email": "target@example.com", "department": "IT"}]

        c_id = mgr.create_campaign(name=args.name, template_type=args.template, targets=targets)
        print(f"{GREEN}Created campaign '{args.name}' with ID: {c_id} ({len(targets)} targets){RESET}")

    elif args.action == "launch":
        res = mgr.launch_campaign(args.campaign_id)
        print(f"{GREEN}Campaign {args.campaign_id} launched! Sent {res.get('emails_sent', 0)} simulated emails.{RESET}")

    elif args.action == "report":
        stats = mgr.get_campaign_stats(args.campaign_id)
        print(f"\n{CYAN}Campaign Report for: {args.campaign_id}{RESET}")
        print(f"  Total Targets:        {stats.total_targets}")
        print(f"  Emails Sent:          {stats.emails_sent}")
        print(f"  Open Rate:            {stats.open_rate:.1f}%")
        print(f"  Click Rate:           {YELLOW}{stats.click_rate:.1f}%{RESET}")
        print(f"  Credential Submits:   {RED}{stats.submission_rate:.1f}%{RESET}")
        print(f"  Report Rate:          {GREEN}{stats.report_rate:.1f}%{RESET}")
        print(f"  Vulnerability Index:  {stats.risk_score:.1f}/100\n")


def cmd_train_model(args):
    """Train or evaluate the ML phishing detector."""
    print(f"\n{CYAN}Loading training dataset & training Machine Learning detector...{RESET}")
    detector = PhishingMLDetector()
    data_file = Config.TRAINING_DATA_FILE
    training_data = []
    if os.path.exists(data_file):
        with open(data_file, 'r') as f:
            training_data = json.load(f)

    metrics = detector.train(training_data)
    print(f"{GREEN}Model Training Complete:{RESET}")
    for k, v in metrics.items():
        print(f"  • {k}: {v}")

    # Evaluate
    eval_res = detector.evaluate(training_data[:30])
    print(f"\n{GREEN}Evaluation on Validation Subset:{RESET}")
    print(f"  • Accuracy:  {eval_res.accuracy:.1%}")
    print(f"  • Precision: {eval_res.precision:.1%}")
    print(f"  • Recall:    {eval_res.recall:.1%}")
    print(f"  • F1-Score:  {eval_res.f1:.3f}")

    # Save model
    detector.save_model(Config.MODEL_PATH)
    print(f"\nModel saved to: {Config.MODEL_PATH}\n")


def cmd_quiz(args):
    """Run an interactive awareness quiz in terminal."""
    trainer = AwarenessTrainer()
    questions = trainer.generate_quiz(difficulty=args.difficulty, count=args.count)

    print(f"\n{CYAN}=== Security Awareness Quiz ({args.difficulty.upper()} LEVEL) ==={RESET}\n")
    user_responses = []

    for i, q in enumerate(questions, 1):
        print(f"{BRIGHT}Question {i}/{len(questions)}:{RESET} {q.question}")
        for j, opt in enumerate(q.options):
            print(f"   [{j+1}] {opt}")

        while True:
            try:
                choice = input("\nYour answer (1-4): ").strip()
                ans_idx = int(choice) - 1
                if 0 <= ans_idx < len(q.options):
                    break
            except (ValueError, KeyboardInterrupt):
                pass
            print("Please enter a valid choice (1-4).")

        user_responses.append({
            "question_id": q.question_id,
            "answer": ans_idx,
            "difficulty": args.difficulty
        })

        if ans_idx == q.correct_answer:
            print(f"{GREEN}✓ Correct!{RESET} {q.explanation}\n")
        else:
            print(f"{RED}✗ Incorrect.{RESET} Correct answer: [{q.correct_answer + 1}] {q.options[q.correct_answer]}")
            print(f"Explanation: {q.explanation}\n")

    report = trainer.generate_report_card(user_responses)
    print(f"{CYAN}=== Quiz Assessment Summary ==={RESET}")
    print(f"Score: {report.score_percent}% ({report.correct_answers}/{report.total_questions} correct)")
    if report.strengths:
        print(f"Strengths: {', '.join(report.strengths)}")
    if report.recommendations:
        print(f"Recommendations:")
        for r in report.recommendations:
            print(f"  • {r}")
    print()


def cmd_demo(args):
    """Run a comprehensive live demonstration of all framework capabilities."""
    print(f"{CYAN}{BRIGHT}>>> Starting Automated End-to-End PhishGuard Demonstration <<<{RESET}\n")

    # 1. Phishing Email Generation
    print(f"{BRIGHT}[1/5] Generating Realistic Phishing Simulation Emails...{RESET}")
    gen = PhishingEmailGenerator()
    sim_email = gen.generate_email(
        template_type="password_reset",
        target_name="David Miller",
        target_email="david.miller@acme-corp.com",
        sender_org="Acme Corporate IT",
        sophistication="intermediate"
    )
    print(f"  • Subject:      {sim_email.subject}")
    print(f"  • Sender:       {sim_email.sender_name} <{sim_email.sender_email}>")
    print(f"  • Spoofed From: {sim_email.headers.get('From')}")
    print(f"  • Pixel Tag:    {sim_email.tracking_pixel_id}")
    print(f"  • Link Tag:     {sim_email.phishing_link_id}")

    # 2. Heuristic URL Analyzer
    print(f"\n{BRIGHT}[2/5] Testing URL Phishing Detection Engine...{RESET}")
    url_analyzer = URLAnalyzer()
    test_urls = [
        "https://accounts.google.com/signin",
        "http://g00gle.com.account-update.tk/login",
        "http://192.168.1.100/secure-login/paypal/verify.php"
    ]
    for u in test_urls:
        res = url_analyzer.analyze_url(u)
        color = RED if res.risk_score >= 60 else (YELLOW if res.risk_score >= 30 else GREEN)
        print(f"  • {u} -> {color}{res.risk_level} (Score: {res.risk_score}/100){RESET}")

    # 3. Email Content & Social Engineering Analysis
    print(f"\n{BRIGHT}[3/5] Testing Email Content & NLP Social Engineering Filter...{RESET}")
    email_analyzer = EmailAnalyzer()
    test_email = (
        "URGENT: Your account has been suspended! Immediate action required within 2 hours. "
        "Log in to http://192.168.1.100/verify immediately to confirm your password and restore access."
    )
    email_res = email_analyzer.analyze_email(
        subject="URGENT: Your account has been suspended!",
        body=test_email,
        sender="security@g00gle-support.tk"
    )
    print(f"  • Threat Level:     {RED if email_res.risk_score >= 60 else YELLOW}{email_res.risk_level} ({email_res.risk_score}/100){RESET}")
    print(f"  • SE Tactics:       {', '.join(t.tactic for t in email_res.social_engineering_tactics)}")
    print(f"  • Recommendation:   {email_res.recommended_action}")

    # 4. Machine Learning Model Evaluation
    print(f"\n{BRIGHT}[4/5] Training & Evaluating ML Classifier...{RESET}")
    ml = PhishingMLDetector()
    train_res = ml.train([])
    print(f"  • Model Type:       {train_res.get('model_type')}")
    print(f"  • Training Samples: {train_res.get('samples')}")
    print(f"  • Accuracy:         {train_res.get('accuracy', 0):.1%}")

    # Predict sample
    pred = ml.predict({
        "subject": "Action Required: Reset Password",
        "body": "Click http://192.168.1.1/reset immediately to prevent account termination.",
        "sender": "admin@micros0ft.tk"
    })
    print(f"  • ML Prediction on Suspicious Email: {'IS PHISHING' if pred.is_phishing else 'LEGITIMATE'} (Confidence: {pred.confidence:.0%})")

    # 5. Campaign Lifecycle Simulation
    print(f"\n{BRIGHT}[5/5] Simulating End-to-End Awareness Campaign...{RESET}")
    campaign_mgr = CampaignManager()
    c_id = campaign_mgr.create_campaign(
        name="Demo Executive Drill",
        template_type="ceo_fraud",
        targets=[
            {"name": "Alice Finance", "email": "alice@company.com", "department": "Finance"},
            {"name": "Bob Dev", "email": "bob@company.com", "department": "Engineering"},
            {"name": "Carol HR", "email": "carol@company.com", "department": "HR"}
        ]
    )
    launch_res = campaign_mgr.launch_campaign(c_id)
    stats = campaign_mgr.get_campaign_stats(c_id)
    print(f"  • Campaign Created: {c_id}")
    print(f"  • Emails Simulated: {launch_res.get('emails_sent')}")
    print(f"  • Open Rate:        {stats.open_rate:.1f}%")
    print(f"  • Click Rate:       {stats.click_rate:.1f}%")
    print(f"  • Creds Submitted:  {stats.submission_rate:.1f}%")
    print(f"  • Reported Rate:    {stats.report_rate:.1f}%")

    print(f"\n{GREEN}{BRIGHT}✓ Demonstration completed successfully!{RESET}\n")
    print(f"To launch the web interface, run:\n  {CYAN}python main.py dashboard{RESET}\n")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="PhishGuard - Phishing Attack Simulation & Detection Framework"
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # dashboard
    p_dash = subparsers.add_parser("dashboard", help="Start the Flask web dashboard")
    p_dash.add_argument("--host", default="127.0.0.1", help="Host binding (default: 127.0.0.1)")
    p_dash.add_argument("--port", type=int, default=5000, help="Port binding (default: 5000)")
    p_dash.add_argument("--debug", action="store_true", help="Enable Flask debug mode")

    # analyze-url
    p_url = subparsers.add_parser("analyze-url", help="Analyze URL for phishing indicators")
    p_url.add_argument("url", help="Target URL to inspect")

    # analyze-email
    p_email = subparsers.add_parser("analyze-email", help="Inspect email for phishing")
    p_email.add_argument("--subject", required=True, help="Email subject line")
    p_email.add_argument("--sender", required=True, help="Sender email address")
    p_email.add_argument("--body", required=True, help="Body text or snippet")

    # campaign
    p_camp = subparsers.add_parser("campaign", help="Manage phishing campaigns")
    p_camp.add_argument("action", choices=["create", "launch", "report"], help="Campaign action")
    p_camp.add_argument("--name", default="Security Simulation", help="Campaign name")
    p_camp.add_argument("--template", default="password_reset", help="Template type")
    p_camp.add_argument("--targets", default="targets.csv", help="Path to targets CSV/text file")
    p_camp.add_argument("--campaign-id", help="Campaign ID for launch/report")

    # train-model
    p_train = subparsers.add_parser("train-model", help="Train ML phishing detection model")

    # quiz
    p_quiz = subparsers.add_parser("quiz", help="Take an interactive awareness quiz")
    p_quiz.add_argument("--difficulty", choices=["beginner", "intermediate", "advanced"], default="beginner")
    p_quiz.add_argument("--count", type=int, default=5, help="Number of questions (default: 5)")

    # demo
    p_demo = subparsers.add_parser("demo", help="Run full automated system demonstration")

    args = parser.parse_args()

    if not args.subcommand:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "dashboard": cmd_dashboard,
        "analyze-url": cmd_analyze_url,
        "analyze-email": cmd_analyze_email,
        "campaign": cmd_campaign,
        "train-model": cmd_train_model,
        "quiz": cmd_quiz,
        "demo": cmd_demo,
    }

    handler = handlers.get(args.subcommand)
    if handler:
        handler(args)


if __name__ == "__main__":
    main()
