
import csv
from pathlib import Path
import sys
from email.utils import parseaddr
from urllib.parse import urlparse

print("=" * 60)
print("                 EMAIL RISK ANALYZER")
print("=" * 60)

# STEP 1: Find the CSV dataset
script_folder = Path(__file__).resolve().parent

possible_locations = [
    script_folder / "email_samples.csv",
    script_folder.parent / "email_samples.csv",
    script_folder / "cyber_email_risk_samples" / "email_samples.csv"
]

csv_file = None

for location in possible_locations:
    if location.exists():
        csv_file = location
        break

if csv_file is None:
    print("\nERROR: email_samples.csv file not found!")
    sys.exit()

# STEP 2: Load dataset
try:
    with open(csv_file, "r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        emails = list(reader)

except Exception as error:
    print("\nERROR while reading CSV:", error)
    sys.exit()

if not emails:
    print("\nNo email records found!")
    sys.exit()

print("\nDataset Loaded Successfully!")
print("Total Emails:", len(emails))

# STEP 3: Suspicious keywords
urgent_keywords = [
    "urgent", "immediately", "verify", "suspended",
    "action required", "password", "account locked",
    "payment", "click here", "update your account",
    "confirm your identity", "limited time"
]

# STEP 4: Extract sender domain
def get_email_domain(email_address):
    name, address = parseaddr(email_address)

    if "@" in address:
        return address.split("@")[-1].lower().strip()

    return ""

# STEP 5: Extract link domain
def get_link_domain(link):
    link = link.strip().lower()

    if not link:
        return ""

    if "://" not in link:
        link = "https://" + link

    parsed_url = urlparse(link)

    return parsed_url.netloc.replace("www.", "")

# STEP 6: Analyze email
def analyze_email(email):

    risk_score = 0
    reasons = []

    # SPF check
    spf = email.get("SPF", "").strip().upper()

    if spf == "FAIL":
        risk_score += 30
        reasons.append("SPF authentication failed")

    elif spf in ["NONE", "SOFTFAIL"]:
        risk_score += 15
        reasons.append("SPF missing or soft-failed")

    # DKIM check
    dkim = email.get("DKIM", "").strip().upper()

    if dkim == "FAIL":
        risk_score += 25
        reasons.append("DKIM authentication failed")

    elif dkim in ["NONE", "MISSING"]:
        risk_score += 15
        reasons.append("DKIM authentication missing")

    # Sender and Reply-To comparison
    sender_domain = get_email_domain(email.get("From", ""))
    reply_domain = get_email_domain(email.get("ReplyTo", ""))

    if sender_domain and reply_domain:
        if sender_domain != reply_domain:
            risk_score += 20
            reasons.append("Sender and Reply-To domains mismatch")

    # Urgent keyword check
    subject = email.get("Subject", "").lower()

    found_keywords = [
        word for word in urgent_keywords if word in subject
    ]

    if found_keywords:
        risk_score += min(len(found_keywords) * 5, 15)
        reasons.append("Urgent keywords: " + ", ".join(found_keywords))

    # Sender and link domain comparison
    link_domain = get_link_domain(
        email.get("BodyLinkDomain", "")
    )

    if sender_domain and link_domain:
        if sender_domain != link_domain:
            risk_score += 20
            reasons.append("Sender and link domains mismatch")

    # Attachment check
    attachment = email.get("HasAttachment", "").strip().lower()

    if attachment in ["yes", "true", "1"]:
        risk_score += 5
        reasons.append("Email contains an attachment")

    # Calculate final score
    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        risk_level = "HIGH"
    elif risk_score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return risk_score, risk_level, reasons

# STEP 7: Analyze all emails
results = []

print("\n" + "=" * 60)
print("                 EMAIL ANALYSIS RESULTS")
print("=" * 60)

for email in emails:

    score, level, reasons = analyze_email(email)

    result = {
        "MessageID": email.get("MessageID", ""),
        "From": email.get("From", ""),
        "ReplyTo": email.get("ReplyTo", ""),
        "Subject": email.get("Subject", ""),
        "SPF": email.get("SPF", ""),
        "DKIM": email.get("DKIM", ""),
        "HasAttachment": email.get("HasAttachment", ""),
        "BodyLinkDomain": email.get("BodyLinkDomain", ""),
        "RiskScore": score,
        "RiskLevel": level,
        "Reasons": "; ".join(reasons) if reasons else "No major indicators found",
        "ExpectedLabel": email.get("ExpectedLabel", "")
    }

    results.append(result)

    print("\nMessage ID:", result["MessageID"])
    print("Subject:", result["Subject"])
    print("Risk Score:", score, "/ 100")
    print("Risk Level:", level)

    for reason in reasons:
        print("-", reason)

    if not reasons:
        print("- No major suspicious indicators found")

# STEP 8: Risk summary
high_count = sum(1 for item in results if item["RiskLevel"] == "HIGH")
medium_count = sum(1 for item in results if item["RiskLevel"] == "MEDIUM")
low_count = sum(1 for item in results if item["RiskLevel"] == "LOW")

print("\n" + "=" * 60)
print("                   RISK SUMMARY")
print("=" * 60)

print("Total Emails Analyzed:", len(results))
print("High Risk Emails:", high_count)
print("Medium Risk Emails:", medium_count)
print("Low Risk Emails:", low_count)

# STEP 9: Export analysis results to CSV
report_file = script_folder / "email_analysis_report.csv"

fieldnames = [
    "MessageID",
    "From",
    "ReplyTo",
    "Subject",
    "SPF",
    "DKIM",
    "HasAttachment",
    "BodyLinkDomain",
    "RiskScore",
    "RiskLevel",
    "Reasons",
    "ExpectedLabel"
]

try:
    with open(report_file, "w", newline="", encoding="utf-8-sig") as file:

        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(results)

    print("\nAnalysis Report Generated Successfully!")
    print("Report Location:")
    print(report_file)

except Exception as error:
    print("\nERROR while generating report:", error)

print("\n" + "=" * 60)
print("             EMAIL ANALYSIS COMPLETED")
print("=" * 60)
