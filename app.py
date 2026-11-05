from datetime import datetime
import json
import os
import re
import sqlite3
import requests
from dotenv import load_dotenv

load_dotenv()
# ---------------------------------------------------------
# 0. API KEY CONFIGURATION (Replace with your actual key)
# ---------------------------------------------------------
API_KEY = os.environ["GNANI_API_KEY"]


DB_NAME = "caller_history.db"

# ---------------------------------------------------------
# 0. TRUSTED CONTACTS WHITELIST (Bypasses Scam Check)
# ---------------------------------------------------------
TRUSTED_CONTACTS = [
    "111122223333",
    "999988887777",  # Add your family or test contact 12-digit numbers here
]


# ---------------------------------------------------------
# 1. SQLITE REPEAT-CALLER MEMORY SETUP
# ---------------------------------------------------------
def init_db():
  """Creates the SQLite database automatically if it doesn't exist."""
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()
  cursor.execute("""
        CREATE TABLE IF NOT EXISTS call_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_number TEXT,
            timestamp TEXT,
            risk_level TEXT,
            score INTEGER,
            words_found TEXT
        )
    """)
  conn.commit()
  conn.close()


def check_caller_history(phone_number):
  """Checks SQLite database to see if this 12-digit dummy number called before."""
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()
  cursor.execute(
      """
        SELECT risk_level, score, timestamp FROM call_logs 
        WHERE phone_number = ? ORDER BY id DESC
    """,
      (phone_number,),
  )
  records = cursor.fetchall()
  conn.close()

  if records:
    print(
        f"\n⚠️ REPEAT CALLER ALERT: [{phone_number}] has called"
        f" {len(records)} time(s) before. Last risk: {records[0][0]} (Score:"
        f" {records[0][1]})"
    )
  else:
    print(f"\nℹ️ First-time caller from dummy number: [{phone_number}]")


def log_call(phone_number, risk_level, score, words):
  """Saves the current call details into SQLite and exports a JSON audit log."""
  timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

  # 1. Save to SQLite Database
  conn = sqlite3.connect(DB_NAME)
  cursor = conn.cursor()
  cursor.execute(
      """
        INSERT INTO call_logs (phone_number, timestamp, risk_level, score, words_found)
        VALUES (?, ?, ?, ?, ?)
    """,
      (phone_number, timestamp, risk_level, score, str(words)),
  )
  conn.commit()
  conn.close()

  # 2. Export Audit Report to JSON (Enterprise-grade feature for judges)
  audit_data = {
      "phone_number": phone_number,
      "timestamp": timestamp,
      "risk_level": risk_level,
      "total_score": score,
      "triggers_detected": words,
  }
  with open("call_audit_report.json", "w", encoding="utf-8") as json_file:
    json.dump(audit_data, json_file, indent=4, ensure_ascii=False)
  print(
      "📁 [Audit Log]: Structured JSON report saved to"
      " 'call_audit_report.json'"
  )


# ---------------------------------------------------------
# 2. SIGNS & RISK SCORING
# ---------------------------------------------------------
SIGNS = {
    "authority": (
        2,
        [
            "cbi",
            "police",
            "पुलिस",
            "cyber crime",
            "क्राइम ब्रांच",
            "inspector",
            "इंस्पेक्टर",
            "customs",
            "कस्टम",
            "बैंक",
            "bank",
            "income tax",
            "इनकम टैक्स",
        ],
    ),
    "threat": (
        3,
        [
            "arrest",
            "अरेस्ट",
            "drugs",
            "ड्रग्स",
            "case",
            "केस",
            "पकड़ा",
            "ब्लॉक",
            "block",
            "बंद हो जाएगा",
        ],
    ),
    "secrecy": (
        3,
        ["मत बताइए", "मत बताइये", "मत बताना", "किसी को भी मत", "किसी को मत"],
    ),
    "stay_on_line": (2, ["बने रहिए", "बने रहिये", "लाइन पर"]),
    "asks_secret": (
        4,
        [
            "ओटीपी",
            "otp",
            "पिन",
            "pin",
            "पासवर्ड",
            "password",
            "details",
            "डिटेल्स",
            "खाता नंबर",
            "account number",
        ],
    ),
    "asks_money": (
        4,
        [
            "ट्रांसफर",
            "transfer",
            "पैसे भेज",
            "भेज दीजिए",
            "भेज दो",
            "भेजिए",
            "फीस",
            "upi",
        ],
    ),
    "asks_link": (
        4,
        ["लिंक", "link", "क्लिक", "click", "डाउनलोड", "download", "apk", "ऐप"],
    ),
    "lure": (
        3,
        [
            "इनाम",
            "बधाई",
            "जीता",
            "लॉटरी",
            "lottery",
            "prize",
            "रिफंड",
            "refund",
            "cashback",
        ],
    ),
    "emergency": (
        3,
        ["मुसीबत", "accident", "एक्सीडेंट", "अस्पताल", "hospital", "पुलिस ने पकड़"],
    ),
    "urgency": (2, ["जल्दी", "अभी", "तुरंत", "फौरन", "urgent"]),
}

def risk_level(found_words):
  score = sum(SIGNS[cat][0] for cat in found_words.keys())
  categories = set(found_words.keys())

  # Set threshold to 10 so multi-sign scam calls hit HIGH correctly
  if len(categories) >= 3 and score >= 11:
    return score, "HIGH"
  if score >= 6 or "asks_secret" in categories:
    return score, "MEDIUM"
  return score, "LOW"



# ---------------------------------------------------------
# 3. API FUNCTIONS (Multilingual STT & TTS)
# ---------------------------------------------------------
def transcribe(path):
  with open(path, "rb") as f:
    r = requests.post(
        "https://api.vachana.ai/stt/v3",
        headers={"X-API-Key-ID": API_KEY},
        files={"audio_file": (path, f)},
        data={
            "model": "prisma-v3.0",
            "language_code": "hi-IN,en-IN",
        },
        timeout=60,
    )
  if r.status_code != 200:
    print("Transcription failed:", r.status_code, r.text)
    return None
  return r.json()["transcript"]


def speak_warning(warning_file, warning_text):
  if not os.path.exists(warning_file):
    r = requests.post(
        "https://api.vachana.ai/api/v1/tts/inference",
        headers={"X-API-Key-ID": API_KEY, "Content-Type": "application/json"},
        json={
            "text": warning_text,
            "model": "timbre-v2.5",
            "voice": "Nalini",
            "audio_config": {
                "sample_rate": 48000,
                "num_channels": 1,
                "sample_width": 2,
                "encoding": "linear_pcm",
                "container": "wav",
            },
        },
    )
    if r.status_code != 200:
      print("Warning voice failed:", r.status_code, r.text)
      return
    with open(warning_file, "wb") as f:
      f.write(r.content)
  os.startfile(warning_file)


# ---------------------------------------------------------
# 4. MAIN EXECUTION PROGRAM
# ---------------------------------------------------------
if __name__ == "__main__":
  init_db()

  print("==================================================")
  print("      🛡️ NANI BOT - SCAM CALL GUARD (v3.0)        ")
  print("==================================================")

  caller_number = input(
      "Enter 12-digit dummy number (e.g., 123456789012): "
  ).strip()
  if not caller_number or len(caller_number) != 12:
    caller_number = "123456789012"

  # Whitelist check
  if caller_number in TRUSTED_CONTACTS:
    print(
        f"\n🛡️ SAFE CONTACT: [{caller_number}] is whitelisted. Bypassing"
        " analysis."
    )
    raise SystemExit

  answer = input("Do you want to analyse this call? (yes/no): ").strip().lower()
  if answer != "yes":
    print("Okay, nothing was analysed. Call allowed normally.")
    raise SystemExit

  # Check SQLite repeat memory
  check_caller_history(caller_number)

  audio_file = input(
      "Enter audio filename to test (default: scammer1_30s.wav): "
  ).strip()
  if not audio_file:
    audio_file = "scammer1_30s.wav"

  print(
      f"\n[Multilingual STT Active] Listening to call audio from"
      f" {caller_number}..."
  )
  transcript = transcribe(audio_file)
  if transcript is None:
    raise SystemExit

  sentences = [s.strip() for s in re.split(r"[।?.!]", transcript) if s.strip()]
  found_words = {}
  alarm_done = False

  print("\n--- Live Sentence Analysis & Trigger Highlighting ---")
  for s in sentences:
    text = s.lower()
    for c, (pts, words) in SIGNS.items():
      for w in words:
        if w in text:
          if c not in found_words:
            found_words[c] = []
          if w not in found_words[c]:
            found_words[c].append(w)

    score, level = risk_level(found_words)
    print(f"Sentence: {s[:50]}...")
    print(f"   score: {score} | risk: {level}")

    if found_words:
      triggers = [
          f"'{w}' ({c})" for c, words in found_words.items() for w in words
      ]
      print(f"   Triggered: {', '.join(triggers)}")

    if level == "HIGH" and not alarm_done:
      print("   *** HIGH RISK: possible scam call detected! ***")
      warning_file = "warning.wav"
      WARNING_TEXT = (
          "सावधान! यह स्कैम कॉल हो सकता है। अपनी कोई भी जानकारी साझा न करें।"
      )
      speak_warning(warning_file, WARNING_TEXT)
      alarm_done = True

  final_score, final_level = risk_level(found_words)
  all_triggers = [
      f"'{w}' ({c})" for c, words in found_words.items() for w in words
  ]

  print("\n" + "=" * 55)
  print(
      f"FINAL RESULT | Risk Level: {final_level} | Total Score:"
      f" {final_score}"
  )
  print(
      "Triggered Words Found:"
      f" {', '.join(all_triggers) if all_triggers else 'None'}"
  )
  print("=" * 55)

  log_call(caller_number, final_level, final_score, all_triggers)