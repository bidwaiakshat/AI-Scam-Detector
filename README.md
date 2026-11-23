# AI-Scam-Detector

CampusCheck is a local two-layer scanner that checks college WhatsApp forwards for student scams, fake paid internships, and malware links. It runs on Python, Streamlit, Ollama, and the VirusTotal Public API.

## Why This Exists

Tools like VirusTotal and Google Safe Browsing catch technical threats like malware and blacklisted phishing sites. Most scams in Indian college WhatsApp groups skip malware completely. A typical forward promises a paid internship, shares a `forms.gle` link, lists a personal `@gmail.com` HR contact, and asks for a ₹499 registration fee via UPI. Because Google Forms is a clean domain, standard link scanners mark it safe.

CampusCheck checks the message context first, then scans any extracted URLs against a live malware database.

## How It Works

**Layer 1: Local AI Analysis (`qwen2.5:3b` via Ollama)**
Reads the full pasted message at temperature `0` to catch common campus social-engineering patterns:
* Requests for UPI payments, deposits, or training fees tied to internships or jobs
* Personal email addresses (`@gmail.com`, `@yahoo.com`) pretending to be official HR
* Artificial urgency ("apply in 2 hours", "only 12 seats left")
* Free form links asking for Aadhaar numbers, bank details, or passwords

**Layer 2: Malware and Domain Scan (VirusTotal Public API v3)**
Extracts web links from the message using regex. It strips out email addresses so they are not scanned as websites, and adds `https://` to bare links like `bit.ly/xyz` or `forms.gle/abc`. Each link is checked against VirusTotal with a 5-second timeout. If the network drops or the API rate limit hits, the app falls back to Layer 1 without crashing.

## Project Structure

```text
AI Scam Detector/
├── app.py              # Main Streamlit app with Ollama + VirusTotal logic
├── .env                # Local API key (never committed to GitHub)
├── .gitignore          # Keeps .env and Python cache out of version control
└── README.md           # Project documentation
