import os
import re
import math
import urllib.parse
from flask import Flask, request, jsonify, send_from_directory
import tldextract

app = Flask(__name__, static_folder="static")

POPULAR_DOMAINS = [
    "google", "youtube", "facebook", "twitter", "instagram", "amazon", "apple",
    "microsoft", "netflix", "linkedin", "github", "reddit", "wikipedia", "yahoo",
    "twitch", "ebay", "paypal", "dropbox", "spotify", "pinterest", "tumblr",
    "wordpress", "adobe", "salesforce", "zoom", "slack", "discord", "tiktok",
    "whatsapp", "telegram", "snapchat", "chase", "wellsfargo", "bankofamerica",
    "citibank", "barclays", "hsbc", "payoneer", "stripe", "coinbase", "binance",
]

SHORTENING_SERVICES = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "clck.ru", "rb.gy", "cutt.ly", "shorturl.at",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".online", ".site",
    ".click", ".link", ".work", ".party", ".trade", ".science", ".racing",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "log-in", "secure", "security",
    "update", "verify", "verification", "confirm", "confirmation", "account",
    "password", "credential", "banking", "payment", "paypal", "invoice",
    "suspended", "unusual", "alert", "notification", "validate", "wallet",
    "recover", "restore", "unlock", "limited", "access", "urgent",
]

# name → (display name, category)
TRACKING_PARAMS = {
    "utm_source":    ("UTM Source",              "Analytics"),
    "utm_medium":    ("UTM Medium",              "Analytics"),
    "utm_campaign":  ("UTM Campaign",            "Analytics"),
    "utm_term":      ("UTM Term",                "Analytics"),
    "utm_content":   ("UTM Content",             "Analytics"),
    "utm_id":        ("UTM ID",                  "Analytics"),
    "fbclid":        ("Facebook Click ID",       "Advertising"),
    "gclid":         ("Google Ads Click ID",     "Advertising"),
    "msclkid":       ("Microsoft Ads Click ID",  "Advertising"),
    "ttclid":        ("TikTok Click ID",         "Advertising"),
    "twclid":        ("Twitter/X Click ID",      "Advertising"),
    "li_fat_id":     ("LinkedIn Click ID",       "Advertising"),
    "dclid":         ("DoubleClick Click ID",    "Advertising"),
    "sscid":         ("ShareASale Click ID",     "Advertising"),
    "zanpid":        ("Zanox/Awin Click ID",     "Advertising"),
    "mc_eid":        ("Mailchimp Email ID",      "Email Tracking"),
    "mc_cid":        ("Mailchimp Campaign ID",   "Email Tracking"),
    "_hsenc":        ("HubSpot Email Tracking",  "Email Tracking"),
    "_hsmi":         ("HubSpot Message ID",      "Email Tracking"),
    "vero_id":       ("Vero Email ID",           "Email Tracking"),
    "_ga":           ("Google Analytics Client", "Analytics"),
    "_gl":           ("Google Analytics Linker", "Analytics"),
    "s_cid":         ("Adobe Analytics",         "Analytics"),
    "igshid":        ("Instagram Share ID",      "Social"),
    "ref":           ("Referrer Tracking",       "Analytics"),
    "affiliate_id":  ("Affiliate ID",            "Affiliate"),
    "aff_id":        ("Affiliate ID",            "Affiliate"),
    "partner":       ("Partner Tracking",        "Affiliate"),
}

# domain → (display name, category)
TRACKING_DOMAINS = {
    "google-analytics.com":       ("Google Analytics",    "Analytics"),
    "analytics.google.com":       ("Google Analytics",    "Analytics"),
    "googletagmanager.com":       ("Google Tag Manager",  "Analytics"),
    "googleadservices.com":       ("Google Ads",          "Advertising"),
    "googlesyndication.com":      ("Google AdSense",      "Advertising"),
    "doubleclick.net":            ("Google DoubleClick",  "Advertising"),
    "connect.facebook.net":       ("Facebook Pixel",      "Advertising"),
    "hotjar.com":                 ("Hotjar",              "Behavioral"),
    "static.hotjar.com":          ("Hotjar",              "Behavioral"),
    "mixpanel.com":               ("Mixpanel",            "Analytics"),
    "amplitude.com":              ("Amplitude",           "Analytics"),
    "cdn.segment.com":            ("Segment",             "Analytics"),
    "api.segment.io":             ("Segment",             "Analytics"),
    "intercom.io":                ("Intercom",            "Behavioral"),
    "hs-analytics.net":           ("HubSpot",             "Analytics"),
    "ads-twitter.com":            ("Twitter Ads",         "Advertising"),
    "snap.licdn.com":             ("LinkedIn Insight",    "Advertising"),
    "pintrk.com":                 ("Pinterest Tag",       "Advertising"),
    "mc.yandex.ru":               ("Yandex Metrica",      "Analytics"),
    "clarity.ms":                 ("Microsoft Clarity",   "Behavioral"),
    "mouseflow.com":              ("Mouseflow",           "Behavioral"),
    "crazyegg.com":               ("Crazy Egg",           "Behavioral"),
    "fullstory.com":              ("FullStory",           "Behavioral"),
    "logrocket.io":               ("LogRocket",           "Behavioral"),
    "heap.io":                    ("Heap Analytics",      "Analytics"),
    "matomo.cloud":               ("Matomo",              "Analytics"),
    "plausible.io":               ("Plausible",           "Analytics"),
    "newrelic.com":               ("New Relic",           "Analytics"),
    "bugsnag.com":                ("Bugsnag",             "Analytics"),
    "sentry.io":                  ("Sentry",              "Analytics"),
    "scorecardresearch.com":      ("Comscore",            "Advertising"),
    "quantserve.com":             ("Quantcast",           "Advertising"),
    "adnxs.com":                  ("AppNexus/Xandr",      "Advertising"),
    "criteo.com":                 ("Criteo",              "Advertising"),
    "outbrain.com":               ("Outbrain",            "Advertising"),
    "taboola.com":                ("Taboola",             "Advertising"),
    "amazon-adsystem.com":        ("Amazon Ads",          "Advertising"),
}


def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[len(s2)]


def url_entropy(url):
    if not url:
        return 0
    freq = {}
    for ch in url:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(url)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def check_trackers(raw_url, parsed):
    found = []
    seen = set()

    hostname = (parsed.hostname or "").lower()
    for td, (name, category) in TRACKING_DOMAINS.items():
        if hostname == td or hostname.endswith("." + td):
            if name not in seen:
                seen.add(name)
                found.append({"name": name, "category": category, "detail": f"Tracker domain: {hostname}"})

    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    for param in query_params:
        p = param.lower()
        if p in TRACKING_PARAMS:
            name, category = TRACKING_PARAMS[p]
            if name not in seen:
                seen.add(name)
                found.append({"name": name, "category": category, "detail": f"URL parameter: {param}"})

    return found


def check_phishing(url):
    flags = []
    score = 0

    raw_url = url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        return {"error": "Invalid URL format"}

    ext = tldextract.extract(raw_url)
    domain = ext.domain
    suffix = ext.suffix
    subdomain = ext.subdomain
    hostname = parsed.hostname or ""
    full_url = raw_url

    # 1. IP address used as hostname
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if hostname and ip_pattern.match(hostname):
        score += 30
        flags.append("IP address used instead of a domain name")

    # 2. URL length
    if len(full_url) > 100:
        score += 20
        flags.append(f"Unusually long URL ({len(full_url)} characters)")
    elif len(full_url) > 75:
        score += 10
        flags.append(f"Long URL ({len(full_url)} characters)")

    # 3. HTTPS
    if parsed.scheme != "https":
        score += 10
        flags.append("No HTTPS — connection is not encrypted")
    else:
        score -= 5

    # 4. URL shortening service
    netloc = parsed.netloc.lower().replace("www.", "")
    if any(netloc == s or netloc.endswith("." + s) for s in SHORTENING_SERVICES):
        score += 20
        flags.append("URL shortening service detected — hides the real destination")

    # 5. @ symbol in URL
    if "@" in full_url:
        score += 20
        flags.append("'@' symbol in URL — browser ignores everything before it")

    # 6. Double slash redirect
    path = parsed.path
    if "//" in path:
        score += 10
        flags.append("Double slash in URL path — possible redirect trick")

    # 7. Dash in domain name
    if domain and "-" in domain:
        score += 8
        flags.append("Hyphens in domain name — common in phishing domains")

    # 8. Subdomain depth
    if subdomain:
        sub_parts = [s for s in subdomain.split(".") if s]
        if len(sub_parts) >= 3:
            score += 15
            flags.append(f"Deep subdomain nesting ({len(sub_parts)} levels) — suspicious")
        elif len(sub_parts) == 2:
            score += 5
            flags.append("Multiple subdomains detected")

    # 9. Suspicious TLD
    if suffix and ("." + suffix.split(".")[-1]) in SUSPICIOUS_TLDS:
        score += 15
        flags.append(f"Suspicious top-level domain (.{suffix.split('.')[-1]})")

    # 10. Suspicious keywords in URL
    url_lower = full_url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    if matched_keywords:
        keyword_score = min(len(matched_keywords) * 8, 30)
        score += keyword_score
        flags.append(f"Suspicious keywords in URL: {', '.join(matched_keywords[:5])}")

    # 11. Typosquatting detection
    if domain:
        best_match = None
        best_dist = 999
        for pop in POPULAR_DOMAINS:
            if domain == pop:
                best_dist = 0
                break
            d = levenshtein(domain.lower(), pop)
            if d < best_dist:
                best_dist = d
                best_match = pop
        if 0 < best_dist <= 2 and best_match:
            score += 35
            flags.append(f"Domain '{domain}' closely resembles '{best_match}' — possible typosquatting")

    # 12. Domain length
    if domain and len(domain) > 30:
        score += 10
        flags.append(f"Unusually long domain name ({len(domain)} characters)")

    # 13. Non-standard port
    port = parsed.port
    if port and port not in (80, 443, 8080, 8443):
        score += 10
        flags.append(f"Unusual port number ({port})")

    # 14. URL entropy (randomness)
    entropy = url_entropy(full_url)
    if entropy > 4.5:
        score += 8
        flags.append("High URL character randomness — may be generated/obfuscated")

    # 15. Hex encoding / percent encoding abuse
    pct_encoded = re.findall(r"%[0-9a-fA-F]{2}", full_url)
    if len(pct_encoded) > 4:
        score += 12
        flags.append("Excessive URL encoding — may be hiding malicious content")

    # 16. Multiple dots in hostname
    dot_count = hostname.count(".")
    if dot_count > 4:
        score += 10
        flags.append(f"Many dots in hostname ({dot_count}) — suspicious structure")

    score = max(0, score)

    if score <= 20:
        verdict = "safe"
        label = "Likely Safe"
        message = "This URL shows no significant phishing indicators."
    elif score <= 50:
        verdict = "suspicious"
        label = "Suspicious"
        message = "This URL has some characteristics common in phishing sites. Proceed with caution."
    else:
        verdict = "phishing"
        label = "Likely Phishing"
        message = "This URL shows multiple strong indicators of a phishing attempt. Avoid visiting it."

    trackers = check_trackers(raw_url, parsed)

    return {
        "url": raw_url,
        "score": score,
        "verdict": verdict,
        "label": label,
        "message": message,
        "flags": flags,
        "flag_count": len(flags),
        "trackers": trackers,
        "tracker_count": len(trackers),
    }


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = check_phishing(url)
    return jsonify(result)


@app.route("/api/healthz")
def health():
    return jsonify({"status": "ok"})



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=False)
