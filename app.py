import base64
import os
import re
import ollama
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")


def extract_urls(text):
    # Strip email addresses first so gmail.com is not treated as a web link
    text_no_emails = re.sub(r"\S+@\S+", "", text)
    pattern = r"(?:https?://[^\s]+|www\.[^\s]+|\b[a-zA-Z0-9-]+\.(?:com|in|org|net|edu|gle|ly|co|io|site|xyz|me)(?:/[^\s]*)?)"
    matches = re.findall(pattern, text_no_emails, flags=re.IGNORECASE)

    urls = []
    for url in matches:
        url = url.rstrip(".,!?)")
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if url not in urls:
            urls.append(url)
    return urls


st.title("CampusCheck: Scam & Link Scanner")

message = st.text_area("Paste the WhatsApp message or link:")

if st.button("Check Message"):
    if not message.strip():
        st.warning("Please paste a message first.")
    else:
        # Layer 1: Local Ollama (Social-Engineering Check)
        st.subheader("Layer 1: AI Scam Analysis")
        prompt = f"""Check this college WhatsApp/Mail message for student scams (fake paid internships, UPI fees, personal Gmail HR contacts, fake urgency(Every company does this for marketing, So see to what extent they are creating urgency), or Google Forms asking for money/IDs). Also check if company name is mentioned or not. Dont be too strict. Suggest what the user should to verify if it is trusted or not. Like if company name is visible to them then go to their official website and crosscheck. Also keep in mind that all the messages are for first year college students. So paid internship is unlikely.
Reply with:
1. Risk Level (Low, Medium, or High)
2. 2 or 3 short bullet points explaining why and suggest possible steps for user to take.

Message: {message}"""

        with st.spinner("Analyzing"):
            response = ollama.generate(
                model="qwen2.5:3b",
                prompt=prompt,
            )
            st.write(response["response"])

        # Layer 2: VirusTotal API (Malware Link Check)
        st.subheader("Layer 2: Malware Link Check (VirusTotal)")
        urls = extract_urls(message)

        if not VT_API_KEY:
            st.warning("VT_API_KEY missing. Check your .env file.")
        elif not urls:
            st.info("No web links found in this message.")
        else:
            for url in urls:
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                headers = {"x-apikey": VT_API_KEY}

                try:
                    res = requests.get(
                        f"https://www.virustotal.com/api/v3/urls/{url_id}",
                        headers=headers,
                        timeout=5,
                    )
                    if res.status_code == 200:
                        stats = res.json()["data"]["attributes"]["last_analysis_stats"]
                        st.write(
                            f"**{url}** | Malicious: {stats['malicious']} | "
                            f"Suspicious: {stats['suspicious']} | Clean: {stats['harmless']}"
                        )
                    elif res.status_code == 404:
                        st.info(f"**{url}** is not flagged in VirusTotal (safe or brand new).")
                    elif res.status_code == 429:
                        st.warning("VirusTotal limit hit (4 requests/min). Wait a minute and retry.")
                    else:
                        st.warning(f"VirusTotal error (HTTP {res.status_code}).")
                except Exception:
                    st.warning("Could not reach VirusTotal. Showing Layer 1 only.")