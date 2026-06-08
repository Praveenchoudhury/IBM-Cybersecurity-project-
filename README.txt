PhishGuard — Phishing URL Detector
====================================

REQUIREMENTS
------------
Python 3.9+ must be installed on your machine.
Download it from https://www.python.org/downloads/

SETUP & RUN
-----------
1. Open a terminal (Command Prompt / PowerShell on Windows,
   Terminal on macOS/Linux).

2. Navigate to the folder where you unzipped this project:
     cd path/to/phishguard

3. Install dependencies (one-time):
     pip install -r requirements.txt

4. Start the server:
     python app.py

5. Open your browser and go to:
     http://localhost:3000

FEATURES
--------
- Phishing detection: 16 heuristic checks (IP hostname,
  typosquatting, suspicious TLDs, keywords, entropy, etc.)
- Tracker detection: identifies tracking parameters (UTM,
  fbclid, gclid, msclkid...) and known tracker domains
  (Google Analytics, Facebook Pixel, Hotjar, Clarity, etc.)
- Dark / Light mode toggle (preference saved in browser)
- Download scan results as a .txt report

FILES
-----
  app.py              -- Flask backend + detection logic
  requirements.txt    -- Python dependencies
  static/index.html   -- Frontend (HTML / CSS / JS)
  README.txt          -- This file

HOW TO STOP THE SERVER
----------------------
Press Ctrl+C in the terminal.
