"""
Awareness Trainer Module
========================
Security awareness training with quizzes, educational modules,
and performance tracking.
"""

import json
import os
import random
from dataclasses import dataclass, field
from typing import List, Dict, Optional

from .config import Config


@dataclass
class QuizQuestion:
    """A quiz question for security awareness training."""
    question_id: str
    difficulty: str         # beginner, intermediate, advanced
    topic: str
    question: str
    options: List[str]      # 4 answer options
    correct_answer: int     # Index of correct answer (0-3)
    explanation: str


@dataclass
class QuizResult:
    """Result of a quiz attempt."""
    total_questions: int
    correct_answers: int
    score_percent: float
    strengths: List[str]
    weaknesses: List[str]
    recommendations: List[str]
    details: List[Dict]


class AwarenessTrainer:
    """
    Security awareness training system.

    Provides interactive quizzes, educational content, and progress
    tracking for phishing awareness training.
    """

    # Built-in questions organized by difficulty
    QUESTIONS = {
        "beginner": [
            {
                "id": "b1", "topic": "email_phishing",
                "question": "What is the most common indicator of a phishing email?",
                "options": [
                    "It has a company logo",
                    "Urgent language demanding immediate action",
                    "It was sent during business hours",
                    "It contains a greeting"
                ],
                "correct": 1,
                "explanation": "Phishing emails commonly use urgency to prevent victims from thinking critically. Phrases like 'Act now!' or 'Your account will be suspended' are red flags."
            },
            {
                "id": "b2", "topic": "url_identification",
                "question": "Which of these URLs is most likely a phishing attempt?",
                "options": [
                    "https://www.google.com/login",
                    "https://www.g00gle-security.tk/login",
                    "https://accounts.google.com/signin",
                    "https://mail.google.com"
                ],
                "correct": 1,
                "explanation": "The URL 'g00gle-security.tk' uses number substitution (0 for o), an extra word, and a suspicious .tk TLD - all classic phishing indicators."
            },
            {
                "id": "b3", "topic": "email_phishing",
                "question": "You receive an email from your bank asking you to click a link to verify your account. What should you do?",
                "options": [
                    "Click the link immediately to protect your account",
                    "Forward it to all your contacts as a warning",
                    "Contact your bank directly using their official phone number",
                    "Reply to the email asking for more information"
                ],
                "correct": 2,
                "explanation": "Never click links in unexpected emails. Always contact the organization directly using contact information from their official website or your statements."
            },
            {
                "id": "b4", "topic": "social_engineering",
                "question": "What is social engineering in cybersecurity?",
                "options": [
                    "Building social media profiles",
                    "Manipulating people into revealing confidential information",
                    "Engineering social networks",
                    "Managing a company's social media"
                ],
                "correct": 1,
                "explanation": "Social engineering exploits human psychology rather than technical vulnerabilities. It manipulates people into breaking security procedures or divulging sensitive information."
            },
            {
                "id": "b5", "topic": "reporting_procedures",
                "question": "What should you do if you accidentally clicked a phishing link?",
                "options": [
                    "Ignore it and hope nothing happens",
                    "Delete the email and forget about it",
                    "Report it to IT security immediately and change your passwords",
                    "Turn off your computer for a few hours"
                ],
                "correct": 2,
                "explanation": "Immediately report to IT security, change affected passwords, and monitor your accounts. Quick action can minimize damage."
            },
            {
                "id": "b6", "topic": "password_security",
                "question": "What makes a password strong?",
                "options": [
                    "Using your name and birthday",
                    "A single word from the dictionary",
                    "A long passphrase with mixed characters, numbers, and symbols",
                    "The same password you use everywhere"
                ],
                "correct": 2,
                "explanation": "Strong passwords are long (12+ characters), use mixed case, numbers, and symbols. Passphrases like 'Correct-Horse-Battery-Staple!' are both strong and memorable."
            },
            {
                "id": "b7", "topic": "email_phishing",
                "question": "Which email greeting is most likely from a phishing email?",
                "options": [
                    "Hi John,",
                    "Dear Valued Customer,",
                    "Hello team,",
                    "Good morning Sarah,"
                ],
                "correct": 1,
                "explanation": "Generic greetings like 'Dear Valued Customer' are common in phishing because attackers don't know your name. Legitimate companies usually address you personally."
            },
            {
                "id": "b8", "topic": "url_identification",
                "question": "What does the padlock icon in a browser address bar indicate?",
                "options": [
                    "The website is 100% safe and trustworthy",
                    "The connection is encrypted (HTTPS)",
                    "The website has been verified by police",
                    "Your antivirus is protecting you"
                ],
                "correct": 1,
                "explanation": "The padlock means the connection is encrypted (HTTPS), NOT that the site is trustworthy. Phishing sites can also have HTTPS certificates."
            },
            {
                "id": "b9", "topic": "social_engineering",
                "question": "An email from your 'CEO' asks you to urgently buy gift cards. What is this likely?",
                "options": [
                    "A legitimate request you should fulfill immediately",
                    "A CEO fraud/Business Email Compromise (BEC) attack",
                    "A normal business practice",
                    "An HR initiative"
                ],
                "correct": 1,
                "explanation": "CEO fraud or BEC attacks impersonate executives to pressure employees into financial transactions. Always verify unusual requests through a known phone number."
            },
            {
                "id": "b10", "topic": "reporting_procedures",
                "question": "Why is it important to report phishing emails to IT security?",
                "options": [
                    "It's not important, just delete them",
                    "So IT can block the sender and protect other employees",
                    "To get a reward",
                    "Because it's the law"
                ],
                "correct": 1,
                "explanation": "Reporting helps IT security block threats, warn other employees, and improve email filters. One report can protect the entire organization."
            },
        ],
        "intermediate": [
            {
                "id": "i1", "topic": "email_phishing",
                "question": "What is a 'spear phishing' attack?",
                "options": [
                    "A phishing attack using fishing imagery",
                    "A targeted phishing attack crafted for a specific individual",
                    "A phishing attack sent to everyone in a company",
                    "A phishing attack through social media"
                ],
                "correct": 1,
                "explanation": "Spear phishing targets specific individuals using personal information gathered from social media, company websites, or data breaches. It's more convincing than mass phishing."
            },
            {
                "id": "i2", "topic": "url_identification",
                "question": "What is a homoglyph/IDN homograph attack?",
                "options": [
                    "Using similar-sounding domain names",
                    "Using Unicode characters that look identical to ASCII characters",
                    "Using very long domain names",
                    "Using IP addresses instead of domains"
                ],
                "correct": 1,
                "explanation": "Homoglyph attacks use Unicode characters that visually resemble Latin letters (e.g., Cyrillic 'а' looks like Latin 'a') to create convincing fake domains."
            },
            {
                "id": "i3", "topic": "social_engineering",
                "question": "Which social engineering principle creates artificial time pressure?",
                "options": [
                    "Authority",
                    "Social proof",
                    "Urgency/Scarcity",
                    "Reciprocity"
                ],
                "correct": 2,
                "explanation": "Urgency/Scarcity creates time pressure to prevent critical thinking. 'Act within 24 hours or lose access' forces hasty decisions without verification."
            },
            {
                "id": "i4", "topic": "email_phishing",
                "question": "What does SPF (Sender Policy Framework) protect against?",
                "options": [
                    "Email content being read by attackers",
                    "Unauthorized servers sending emails for a domain",
                    "Attachments containing viruses",
                    "Phishing links in email body"
                ],
                "correct": 1,
                "explanation": "SPF verifies that the sending mail server is authorized by the domain owner. It helps prevent email spoofing by checking DNS records."
            },
            {
                "id": "i5", "topic": "url_identification",
                "question": "What is typosquatting?",
                "options": [
                    "Typing too fast when entering URLs",
                    "Registering domains similar to popular sites with common typos",
                    "Squatting on typing competition results",
                    "Using autocomplete to visit websites"
                ],
                "correct": 1,
                "explanation": "Typosquatting registers domains with common typos (e.g., 'googel.com', 'facbook.com') to catch users who mistype URLs. Always verify URLs carefully."
            },
            {
                "id": "i6", "topic": "social_engineering",
                "question": "What is 'pretexting' in social engineering?",
                "options": [
                    "Adding a prefix to phishing URLs",
                    "Creating a fabricated scenario to gain trust",
                    "Sending pre-written text messages",
                    "Testing email filters before attacking"
                ],
                "correct": 1,
                "explanation": "Pretexting creates a believable backstory (e.g., 'I'm from IT support and need your password to fix an issue') to manipulate victims into compliance."
            },
            {
                "id": "i7", "topic": "password_security",
                "question": "What is credential stuffing?",
                "options": [
                    "Adding extra characters to passwords",
                    "Using stolen credentials from one breach to access other accounts",
                    "Stuffing a password manager with too many entries",
                    "Creating very complex passwords"
                ],
                "correct": 1,
                "explanation": "Credential stuffing automates login attempts using username/password pairs leaked from data breaches. This is why you should never reuse passwords across sites."
            },
            {
                "id": "i8", "topic": "email_phishing",
                "question": "What is a tracking pixel in an email?",
                "options": [
                    "A large promotional image",
                    "A tiny invisible image that reports when an email is opened",
                    "A pixel art attachment",
                    "A QR code embedded in the email"
                ],
                "correct": 1,
                "explanation": "Tracking pixels are 1x1 transparent images that load from a remote server when opened, revealing that the email was read, when, and sometimes from where."
            },
            {
                "id": "i9", "topic": "reporting_procedures",
                "question": "What is the purpose of DMARC (Domain-based Message Authentication)?",
                "options": [
                    "Encrypting email content",
                    "Policy framework combining SPF and DKIM to prevent spoofing",
                    "Scanning attachments for malware",
                    "Blocking all emails from unknown senders"
                ],
                "correct": 1,
                "explanation": "DMARC allows domain owners to publish policies on how to handle emails that fail SPF/DKIM checks, providing a comprehensive anti-spoofing framework."
            },
            {
                "id": "i10", "topic": "url_identification",
                "question": "Why might a phishing URL contain the '@' symbol?",
                "options": [
                    "To include an email address",
                    "To disguise the real destination - browsers ignore text before @",
                    "To make the URL look professional",
                    "It's required for HTTPS"
                ],
                "correct": 1,
                "explanation": "In URLs, text before @ is treated as credentials. 'http://google.com@evil.com' actually goes to evil.com, not google.com. This tricks users into thinking they're visiting a trusted site."
            },
        ],
        "advanced": [
            {
                "id": "a1", "topic": "email_phishing",
                "question": "What is a Business Email Compromise (BEC) attack?",
                "options": [
                    "Hacking into a business email server",
                    "An attack where the attacker impersonates an executive to authorize fraudulent transactions",
                    "Sending business proposals via email",
                    "Compromising email encryption protocols"
                ],
                "correct": 1,
                "explanation": "BEC attacks impersonate executives or trusted partners to trick employees into wire transfers, data disclosure, or other actions. The FBI reports billions in losses annually."
            },
            {
                "id": "a2", "topic": "social_engineering",
                "question": "What is a 'watering hole' attack?",
                "options": [
                    "Attacking water utility websites",
                    "Compromising websites frequently visited by the target group",
                    "Flooding a network with traffic",
                    "Poisoning DNS servers"
                ],
                "correct": 1,
                "explanation": "Watering hole attacks compromise websites that the target group visits regularly (industry forums, news sites) to deliver malware to specific victims."
            },
            {
                "id": "a3", "topic": "email_phishing",
                "question": "What is 'whaling' in the context of phishing?",
                "options": [
                    "Sending phishing to a large number of people",
                    "Phishing attacks specifically targeting C-level executives",
                    "Using whale-themed email templates",
                    "A very large phishing campaign"
                ],
                "correct": 1,
                "explanation": "Whaling targets high-value individuals (CEOs, CFOs, board members) with highly customized attacks. These are sophisticated, well-researched, and potentially devastating."
            },
            {
                "id": "a4", "topic": "url_identification",
                "question": "What is a 'man-in-the-middle' (MITM) phishing attack?",
                "options": [
                    "A phishing attack that intercepts communication between user and legitimate site",
                    "A phishing attack using middleman services",
                    "An attack that only targets middle management",
                    "A phishing attack using two email accounts"
                ],
                "correct": 0,
                "explanation": "MITM phishing relays communication between the victim and legitimate site in real-time, capturing credentials and session tokens, even bypassing 2FA in some cases."
            },
            {
                "id": "a5", "topic": "social_engineering",
                "question": "What makes 'adversary-in-the-middle' (AiTM) phishing particularly dangerous?",
                "options": [
                    "It uses multiple email accounts",
                    "It can bypass multi-factor authentication by stealing session cookies",
                    "It's faster than other phishing attacks",
                    "It only targets military organizations"
                ],
                "correct": 1,
                "explanation": "AiTM phishing proxies the authentication process, capturing session cookies after MFA completion. This allows attackers to hijack authenticated sessions."
            },
            {
                "id": "a6", "topic": "email_phishing",
                "question": "What is 'pharming' and how does it differ from phishing?",
                "options": [
                    "It's the same as phishing but with a different name",
                    "It redirects users to fake sites by poisoning DNS, without requiring them to click a link",
                    "It targets pharmaceutical companies",
                    "It's a type of phone-based phishing"
                ],
                "correct": 1,
                "explanation": "Pharming modifies DNS settings or the hosts file to redirect users to fake websites even when they type the correct URL. Unlike phishing, no link-click is needed."
            },
            {
                "id": "a7", "topic": "password_security",
                "question": "How can hardware security keys (FIDO2/WebAuthn) protect against phishing?",
                "options": [
                    "They encrypt all emails automatically",
                    "They verify the website's identity before authenticating, preventing credential theft on fake sites",
                    "They block phishing emails from arriving",
                    "They make passwords stronger"
                ],
                "correct": 1,
                "explanation": "FIDO2 keys cryptographically verify the website's origin before authenticating. Even if tricked into visiting a fake site, the key won't authenticate - it's phishing-resistant by design."
            },
            {
                "id": "a8", "topic": "reporting_procedures",
                "question": "What is a SOAR (Security Orchestration, Automation, and Response) system's role in phishing defense?",
                "options": [
                    "It blocks all external emails",
                    "It automates incident response workflows for reported phishing",
                    "It trains employees on security awareness",
                    "It encrypts all outgoing emails"
                ],
                "correct": 1,
                "explanation": "SOAR platforms automate the response to phishing reports: extracting IOCs, checking threat intel, quarantining similar emails, and tracking remediation across the organization."
            },
            {
                "id": "a9", "topic": "url_identification",
                "question": "What is 'domain fronting' in the context of advanced phishing?",
                "options": [
                    "Registering domains before legitimate businesses",
                    "Using CDN infrastructure to hide the actual destination of HTTPS requests",
                    "Adding a domain name to the front of an email",
                    "Using front-end frameworks to build phishing sites"
                ],
                "correct": 1,
                "explanation": "Domain fronting uses CDN infrastructure so the visible domain in HTTPS differs from the actual destination. The SNI shows a trusted domain while traffic routes elsewhere."
            },
            {
                "id": "a10", "topic": "social_engineering",
                "question": "What is 'callback phishing' (telephone-oriented attack delivery)?",
                "options": [
                    "Calling back missed calls from unknown numbers",
                    "Emails asking victims to call a number, where operators socially engineer them",
                    "Using callback functions in phishing JavaScript",
                    "Automated phone calls with phishing messages"
                ],
                "correct": 1,
                "explanation": "Callback phishing (TOAD) sends emails with a phone number instead of links, bypassing email link scanners. When victims call, operators guide them to install malware or reveal credentials."
            },
        ],
    }

    TRAINING_MODULES = {
        "email_phishing": {
            "title": "Email Phishing Fundamentals",
            "description": "Learn to identify and handle phishing emails",
            "content": [
                "## What is Email Phishing?\n"
                "Email phishing is a cyber attack where attackers send fraudulent emails "
                "designed to trick recipients into revealing sensitive information, clicking "
                "malicious links, or downloading harmful attachments.\n",
                "## Common Red Flags\n"
                "1. **Urgency/Threats**: 'Act now or your account will be closed!'\n"
                "2. **Generic Greetings**: 'Dear Customer' instead of your name\n"
                "3. **Suspicious Sender**: Domain doesn't match the claimed organization\n"
                "4. **Grammar Errors**: Poor spelling and awkward phrasing\n"
                "5. **Suspicious Links**: Hover to check - does the URL match?\n"
                "6. **Unexpected Attachments**: Especially .exe, .zip, or macro-enabled docs\n"
                "7. **Too Good to Be True**: Free prizes, unexpected refunds\n",
                "## Best Practices\n"
                "- Never click links in unexpected emails\n"
                "- Verify requests through separate channels\n"
                "- Report suspicious emails to IT security\n"
                "- Enable multi-factor authentication\n"
                "- Keep software updated\n"
            ],
        },
        "url_identification": {
            "title": "URL Safety & Identification",
            "description": "Learn to analyze and identify malicious URLs",
            "content": [
                "## Understanding URLs\n"
                "A URL (Uniform Resource Locator) has several parts:\n"
                "```\nhttps://subdomain.domain.tld/path?parameters\n```\n",
                "## Phishing URL Techniques\n"
                "1. **Typosquatting**: g00gle.com, facebo0k.com\n"
                "2. **Subdomain Abuse**: login.google.com.evil.com\n"
                "3. **Homoglyphs**: Using Unicode lookalike characters\n"
                "4. **URL Shorteners**: bit.ly/xyz hiding the real destination\n"
                "5. **IP Addresses**: http://192.168.1.1/login\n"
                "6. **@ Symbol Trick**: http://google.com@evil.com\n",
                "## Safety Tips\n"
                "- Always check the actual domain (between :// and the next /)\n"
                "- Hover over links before clicking\n"
                "- Look for HTTPS, but remember it doesn't guarantee safety\n"
                "- When in doubt, type the URL manually\n"
            ],
        },
        "social_engineering": {
            "title": "Social Engineering Awareness",
            "description": "Understand and defend against manipulation tactics",
            "content": [
                "## The Six Principles of Influence (Cialdini)\n"
                "Attackers exploit these psychological principles:\n",
                "### 1. Authority\n"
                "People comply with requests from authority figures. Attackers "
                "impersonate CEOs, IT admins, or law enforcement.\n",
                "### 2. Urgency\n"
                "Time pressure prevents critical thinking. 'Act within 1 hour!'\n",
                "### 3. Scarcity\n"
                "'Limited offer' or 'Only 2 spots remaining' creates FOMO.\n",
                "### 4. Social Proof\n"
                "'All employees have completed this' makes compliance seem normal.\n",
                "### 5. Reciprocity\n"
                "Offering something free creates obligation to reciprocate.\n",
                "### 6. Fear\n"
                "Threatening consequences triggers emotional, irrational responses.\n",
                "## Defense: STOP-THINK-VERIFY\n"
                "1. **STOP**: Don't react immediately\n"
                "2. **THINK**: Is this request normal? Am I being pressured?\n"
                "3. **VERIFY**: Contact the sender through a known, separate channel\n"
            ],
        },
        "reporting_procedures": {
            "title": "Incident Reporting Procedures",
            "description": "Learn how to properly report security incidents",
            "content": [
                "## Why Report?\n"
                "- Protects other employees from the same attack\n"
                "- Helps IT improve defenses and email filters\n"
                "- Required for compliance and audit purposes\n"
                "- Early reporting minimizes damage\n",
                "## How to Report\n"
                "1. **Don't delete** the suspicious email\n"
                "2. **Don't click** any links or download attachments\n"
                "3. **Forward** the email to your IT security team\n"
                "4. **Note** the sender address, subject, and time received\n"
                "5. **If you clicked**: Immediately change passwords and report\n",
                "## What Happens After You Report?\n"
                "1. IT security analyzes the email\n"
                "2. Malicious indicators are extracted\n"
                "3. Email filters are updated to block similar emails\n"
                "4. Warnings are sent to other potential targets\n"
                "5. The incident is logged for trend analysis\n"
            ],
        },
        "password_security": {
            "title": "Password Security Best Practices",
            "description": "Create and manage strong passwords",
            "content": [
                "## Password Guidelines\n"
                "- Use 12+ characters with mixed case, numbers, and symbols\n"
                "- Use unique passwords for every account\n"
                "- Consider passphrases: 'Correct-Horse-Battery-Staple!'\n"
                "- Never share passwords via email or chat\n",
                "## Multi-Factor Authentication (MFA)\n"
                "- **Something you know**: Password\n"
                "- **Something you have**: Phone, security key\n"
                "- **Something you are**: Fingerprint, face recognition\n"
                "- Enable MFA wherever possible!\n",
                "## Password Managers\n"
                "- Use a reputable password manager\n"
                "- Generate unique passwords for every site\n"
                "- Master password should be very strong and memorized\n"
                "- Consider hardware security keys for critical accounts\n"
            ],
        },
    }

    def __init__(self, quiz_file: Optional[str] = None):
        self.quiz_file = quiz_file or Config.QUIZ_FILE
        self._custom_questions = {}
        self._load_custom_questions()

    def _load_custom_questions(self):
        """Load additional questions from JSON file if available."""
        if os.path.exists(self.quiz_file):
            try:
                with open(self.quiz_file, 'r') as f:
                    self._custom_questions = json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

    def generate_quiz(self, difficulty: str = "beginner",
                       count: int = 10, topic: Optional[str] = None) -> List[QuizQuestion]:
        """
        Generate a quiz with specified parameters.

        Args:
            difficulty: beginner, intermediate, or advanced
            count: Number of questions
            topic: Optional topic filter

        Returns:
            List of QuizQuestion objects
        """
        questions_pool = self.QUESTIONS.get(difficulty, self.QUESTIONS["beginner"])

        # Filter by topic if specified
        if topic:
            questions_pool = [q for q in questions_pool if q["topic"] == topic]

        # Select questions
        selected = questions_pool[:min(count, len(questions_pool))]

        return [
            QuizQuestion(
                question_id=q["id"],
                difficulty=difficulty,
                topic=q["topic"],
                question=q["question"],
                options=q["options"],
                correct_answer=q["correct"],
                explanation=q["explanation"],
            )
            for q in selected
        ]

    def evaluate_response(self, question_id: str, answer: int,
                           difficulty: str = "beginner") -> Dict:
        """
        Evaluate a quiz response.

        Args:
            question_id: ID of the question
            answer: Selected answer index (0-3)
            difficulty: Difficulty level to search

        Returns:
            Dict with is_correct, correct_answer, explanation
        """
        questions = self.QUESTIONS.get(difficulty, [])
        for q in questions:
            if q["id"] == question_id:
                is_correct = answer == q["correct"]
                return {
                    "is_correct": is_correct,
                    "selected_answer": answer,
                    "correct_answer": q["correct"],
                    "correct_text": q["options"][q["correct"]],
                    "explanation": q["explanation"],
                }

        return {"error": f"Question not found: {question_id}"}

    def get_training_module(self, topic: str) -> Optional[Dict]:
        """
        Get educational training content for a topic.

        Args:
            topic: One of email_phishing, url_identification,
                   social_engineering, reporting_procedures, password_security

        Returns:
            Dict with title, description, and content sections
        """
        return self.TRAINING_MODULES.get(topic)

    def get_available_topics(self) -> List[Dict]:
        """List available training topics."""
        return [
            {"topic": key, "title": val["title"], "description": val["description"]}
            for key, val in self.TRAINING_MODULES.items()
        ]

    def generate_report_card(self, user_responses: List[Dict]) -> QuizResult:
        """
        Generate a report card from quiz responses.

        Args:
            user_responses: List of dicts with question_id, answer, difficulty

        Returns:
            QuizResult with score, strengths, weaknesses, recommendations
        """
        total = len(user_responses)
        correct = 0
        topic_scores = {}  # topic -> [correct, total]
        details = []

        for resp in user_responses:
            q_id = resp.get("question_id", "")
            answer = resp.get("answer", -1)
            difficulty = resp.get("difficulty", "beginner")

            result = self.evaluate_response(q_id, answer, difficulty)
            is_correct = result.get("is_correct", False)

            if is_correct:
                correct += 1

            # Find the question's topic
            topic = "general"
            for q_list in self.QUESTIONS.values():
                for q in q_list:
                    if q["id"] == q_id:
                        topic = q["topic"]
                        break

            if topic not in topic_scores:
                topic_scores[topic] = [0, 0]
            topic_scores[topic][1] += 1
            if is_correct:
                topic_scores[topic][0] += 1

            details.append({
                "question_id": q_id,
                "is_correct": is_correct,
                "topic": topic,
                "explanation": result.get("explanation", ""),
            })

        # Determine strengths and weaknesses
        strengths = []
        weaknesses = []
        recommendations = []

        for topic, (c, t) in topic_scores.items():
            rate = c / max(t, 1)
            topic_title = self.TRAINING_MODULES.get(topic, {}).get(
                "title", topic.replace("_", " ").title()
            )

            if rate >= 0.8:
                strengths.append(f"{topic_title} ({rate:.0%})")
            elif rate < 0.5:
                weaknesses.append(f"{topic_title} ({rate:.0%})")
                recommendations.append(
                    f"Review the '{topic_title}' training module"
                )

        score_percent = (correct / max(total, 1)) * 100

        if score_percent < 50:
            recommendations.append("Consider retaking the beginner-level quiz")
            recommendations.append("Schedule regular security awareness sessions")
        elif score_percent < 75:
            recommendations.append("Review weak areas and try intermediate-level quiz")

        return QuizResult(
            total_questions=total,
            correct_answers=correct,
            score_percent=round(score_percent, 1),
            strengths=strengths,
            weaknesses=weaknesses,
            recommendations=recommendations,
            details=details,
        )
