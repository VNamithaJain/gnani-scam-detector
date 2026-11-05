import requests

api_key = "GNANI_API_KEY"

# file name -> what it SHOULD be
files = {
    "scammer1_30s.wav": "scam",
    "generated-audio (13).wav": "scam",
    "generated-audio (14).wav": "scam",
    "generated-audio (10).wav": "normal",
    "generated-audio (11).wav": "normal",
    "generated-audio (12).wav": "normal",
    "Scam_A.wav": "scam",
    "Scam_B.wav": "scam",
    "Normal_A.wav": "normal",
    "Normal_B.wav": "normal",

    
}

SIGNS = {
    "authority": (2, ["cbi", "police", "पुलिस", "cyber crime", "क्राइम ब्रांच", "inspector", "इंस्पेक्टर", "customs", "कस्टम", "बैंक", "bank", "income tax", "इनकम टैक्स"]),
    "threat": (3, ["arrest", "अरेस्ट", "drugs", "ड्रग्स", "case", "केस", "पकड़ा", "ब्लॉक", "block", "बंद हो जाएगा"]),
    "secrecy": (3, ["मत बताइए", "मत बताइये", "मत बताना", "किसी को भी मत", "किसी को मत"]),
    "stay_on_line": (2, ["बने रहिए", "बने रहिये", "लाइन पर"]),
    "asks_secret": (4, ["ओटीपी", "otp", "पिन", "pin", "पासवर्ड", "password", "details", "डिटेल्स", "खाता नंबर", "account number"]),
    "asks_money": (4, ["ट्रांसफर", "transfer", "पैसे भेज", "भेज दीजिए", "भेज दो", "भेजिए", "फीस", "upi"]),
    "asks_link": (4, ["लिंक", "link", "क्लिक", "click", "डाउनलोड", "download", "apk", "ऐप"]),
    "lure": (3, ["इनाम", "बधाई", "जीता", "लॉटरी", "lottery", "prize", "रिफंड", "refund", "cashback"]),
    "emergency": (3, ["मुसीबत", "accident", "एक्सीडेंट", "अस्पताल", "hospital", "पुलिस ने पकड़"]),
    "urgency": (2, ["जल्दी", "अभी", "तुरंत", "फौरन", "urgent"]),
}

def transcribe(path):
    with open(path, "rb") as f:
        r = requests.post(
            "https://api.vachana.ai/stt/v3",
            headers={"X-API-Key-ID": api_key},
            files={"audio_file": (path, f)},
            data={"model": "prisma-v3.0", "language_code": "hi-IN,en-IN"},
            timeout=60,
        )
    if r.status_code != 200:
        print(path, "failed:", r.status_code, r.text[:200])
        return None
    return r.json().get("transcript", "")

def risk_level(found):
    score = sum(SIGNS[c][0] for c in found)
    if len(found) >= 3 and score >= 9:
        return score, "HIGH"
    if score >= 6 or "asks_secret" in found:
        return score, "MEDIUM"
    return score, "LOW"

caught = missed = false_alarms = correct_normal = 0
for name, truth in files.items():
    text = transcribe(name)
    if text is None:
        continue
    t = text.lower()
    found = {c for c, (p, words) in SIGNS.items() if any(w in t for w in words)}
    score, level = risk_level(found)
    flagged = level == "HIGH"
    print(f"{name}: expected {truth}, got {level} (score {score}) {sorted(found)}")
    print("   transcript:", text)
    if truth == "scam" and flagged: caught += 1
    elif truth == "scam": missed += 1
    elif flagged: false_alarms += 1
    else: correct_normal += 1

print()
print("Scam calls caught:", caught, "| missed:", missed)
print("Normal calls fine:", correct_normal, "| false alarms:", false_alarms)