
# Email Risk Analyzer

## Project Overview

Email Risk Analyzer is a Python-based cybersecurity project designed to identify potentially suspicious email records using predefined security rules.

The system analyzes email information, calculates risk scores, and classifies emails into Low Risk, Medium Risk, and High Risk categories.

## Objectives

- Analyze email security indicators.
- Check SPF and DKIM authentication results.
- Identify sender and Reply-To domain mismatches.
- Detect urgency-related keywords in email subjects.
- Compare sender and link domains.
- Calculate email risk scores.
- Generate an automated CSV analysis report.

## Technologies Used

- Python 3.12
- Visual Studio Code
- CSV Module
- Regular Expression (re) Module

## Project Files

| File Name | Description |
|---|---|
| email_risk_analyzer.py | Main Python source code |
| email_samples.csv | Input dataset containing 80 email records |
| email_analysis_report.csv | Generated analysis report |
| Email_Risk_Analyzer_Phishing_Analysis_Report.pdf | Complete project documentation |

## Risk Scoring System

The system uses predefined rules to calculate risk scores.

| Security Indicator | Risk Points |
|---|---:|
| SPF FAIL | +30 |
| SPF NONE or SOFTFAIL | +15 |
| DKIM FAIL | +25 |
| DKIM NONE or MISSING | +15 |
| Sender and Reply-To Domain Mismatch | +20 |
| Each Urgency Keyword | +5 |
| Maximum Urgency Points | +15 |
| Sender and Link Domain Mismatch | +20 |
| Attachment Present | +5 |

Maximum Risk Score: 100.

## Risk Classification

| Risk Score | Risk Category |
|---|---|
| 0–29 | Low Risk |
| 30–59 | Medium Risk |
| 60–100 | High Risk |

## How to Run the Project

1. Install Python 3.12.
2. Download or clone this repository.
3. Open the project folder in Visual Studio Code.
4. Open the terminal.
5. Run the following command:

```bash
python email_risk_analyzer.py
```

The program analyzes the email dataset and generates an output file named `email_analysis_report.csv`.

## Project Results

A total of 80 sample email records were analyzed.

| Risk Category | Number of Emails | Percentage |
|---|---:|---:|
| High Risk | 40 | 50% |
| Medium Risk | 27 | 33.75% |
| Low Risk | 13 | 16.25% |
| Total | 80 | 100% |

## Limitations

- Uses a limited sample dataset.
- Performs rule-based analysis.
- Does not scan actual email body content.
- Does not perform real-time email monitoring.
- Risk scores are estimates, not confirmed phishing verdicts.

## Future Scope

- Real-time email analysis.
- Actual email header analysis.
- Email body scanning.
- Machine Learning integration.
- Suspicious URL detection.
- Attachment security scanning.
- Graphical User Interface (GUI).

## Disclaimer

This project is developed for educational and cybersecurity learning purposes. The risk classification is based on predefined rules and should not be treated as a final security verdict.

## Author

**Mihir Koshti**

**Project:** Workora Cybersecurity Internship – Email Risk Analyzer
