# Career Kit — Resume, LinkedIn & Interview Preparation

Only claim what you have built, run and can explain. Everything below matches this repository. Update the numbers if you change the project.

---

## 41. Resume / LinkedIn proof

### A. Resume bullet points

- Built a privacy-first **password strength analyzer** in Python/Flask. It combines length, character diversity, common-password matching (including leetspeak), and detection of sequences, keyboard walks, repetition, dates and word + number structures into an explainable 0–100 score with specific remediation advice.
- Implemented **entropy estimation** in two forms: the classic L × log₂(N) bound plus a pattern-adjusted estimate that re-prices detected patterns at their attacker cost. This showed why `Password123!` (~79 theoretical bits) is really ~23 bits.
- Applied **secure-coding and data-minimization** controls: an allow-listed SQLite analytics schema with no password column, log redaction, POST-only transport, CSP/no-store headers, rate limiting, a `secrets`-based generator, and a separate Argon2id hashing demo. Verified by **73 automated pytest tests**, including privacy tests that scan logs and raw database bytes.

### B. Two-line project description

A defensive web tool that explains *why* a password is weak (common words, keyboard walks, sequences, repetition, dates, personal details) instead of just checking composition rules. Built with Python/Flask, it analyzes passwords in memory, never stores them, and backs that claim with automated privacy tests.

### C. LinkedIn project description

> **Password Strength Analyzer & Security Suggestion Tool** · Python · Flask · JavaScript · SQLite · pytest
>
> Composition rules say `Password123!` is strong. Attackers say it's one of their first guesses. I built a tool that measures what actually matters: length, unpredictability and resistance to common patterns.
>
> 🔍 Detects common passwords (including leetspeak), sequences, keyboard walks, repetition, years/dates, dictionary words, "word + number" structures and optional personal-info overlap
> 📐 Shows theoretical entropy (L × log₂N) next to a pattern-adjusted estimate, to show why the formula alone misleads
> 🧭 Gives specific fixes, plus hygiene guidance: unique passwords, password managers, MFA
> 🔐 Privacy by design: analysis in memory, no password column anywhere, no passwords in logs, URLs or browser storage, all proven by automated tests
> 🎲 Secure generator using Python's `secrets` (CSPRNG), and a separate Argon2id hashing demo
> 📊 Opt-in, metadata-only dashboard with strength, score, length and weakness distributions
>
> 73 automated tests · policy compliance reported separately from strength · educational, defensive, no cracking functionality.
> Repo: https://github.com/SNischayPrasad/Password-Strength-Analyzer-Security-Tool

### D. Technical skills demonstrated

Password security · Application security · Secure coding (input validation, safe errors, CSP, rate limiting) · IAM concepts (password policy, NIST SP 800-63B, MFA, passwordless) · Password hashing concepts (salting, Argon2id, bcrypt, scrypt, PBKDF2) · Pattern detection (regex, sequence and keyboard-walk algorithms) · Entropy and threat modelling · Privacy by design / data minimization · Python, Flask, REST API design · JavaScript DOM (XSS-safe rendering) · SQLite schema design · pytest (unit, API, privacy tests) · Security awareness writing · Git/GitHub.

### E. GitHub repository description

Privacy-focused cybersecurity tool for evaluating password strength using length, predictability, common-password checks, pattern analysis, entropy concepts, and personalized security recommendations.

---

## 43. Interview preparation — 10 questions and answers

**1. Explain your project.**
It's a defensive web tool that tells you how guessable a password is and why. You type a password, and the Flask backend analyzes it in memory. It measures length and character variety, checks a local common-password list including leetspeak variants, and detects the patterns attackers try first: sequences like 1234, keyboard walks like qwerty, repetition, years and dates, dictionary words, and "word plus number" structures. Optionally it also checks demo personal details. The results feed a transparent scoring engine that produces a 0–100 score and a class, and a suggestion engine that gives specific fixes. I kept policy compliance separate from strength, added a `secrets`-based generator, and built an opt-in dashboard that stores only metadata. The part I'm proudest of is that the privacy claims are tested: 73 pytest tests, including ones that scan the log output and the raw database file for the password.

**2. Why isn't "uppercase + lowercase + number + symbol" a good strength test?**
Because it measures what a password looks like, not how it was chosen. `Password123!` has all four classes, but it's a dictionary word with a capital at the front, "123" and a "!" at the end. That's exactly the layout composition rules push people into, so guessing tools apply it to every word. In my tool it scores 38 (WEAK) even though the naive entropy formula gives it about 79 bits. Modern guidance like NIST SP 800-63B focuses on length and blocking known-bad passwords instead.

**3. What is password entropy, and what's its limitation?**
Entropy is log₂ of the number of equally likely possibilities. For a random password, it's length × log₂(pool size). A random 20-character password from about 86 symbols is roughly 128 bits. The limitation is the word "random": humans don't choose randomly, so the formula overestimates human-chosen passwords. That's why I also compute a pattern-adjusted estimate. For example, a dictionary word is priced at about log₂(dictionary size) bits instead of 8 × 6.6 bits. I label both as estimates, and the guess-time table as "educational estimate only".

**4. How does your pattern detection work?**
Each detector is a small function that returns positions and lengths, never the characters. Sequences: I walk the string and extend runs where consecutive characters differ by +1 or −1 within digits or letters. Keyboard walks: I precompute every substring of four or more characters from QWERTY rows, columns and keypad walks, forwards and backwards, and do a longest-match scan. I skip straight digit runs so 1234 isn't reported twice. Repetition uses the regex `(.+?)\1+`. Dates use regexes plus a validity check on day and month. Structure detection splits a password into letters followed by digits/symbols and checks whether the letter part is a known word. Positions also power the pattern map in the UI.

**5. How should a real system store passwords?**
Never in plaintext, and not with encryption, because encryption is reversible if the key leaks. You store a salted hash from a slow, memory-hard password-hashing function, ideally Argon2id, or scrypt, bcrypt, or PBKDF2 with high iterations. At login you hash the typed password with the stored salt and parameters and compare in constant time. My `demos/hashing_demo.py` shows this with argon2-cffi: the same password hashed twice gives different outputs because of the salt, and verification works one way only. I deliberately kept this demo separate from the analyzer, so nothing typed into the analyzer is ever hashed or stored.

**6. What is a salt and why does it matter?**
A salt is a unique random value generated per password and stored next to the hash. It means two users with the same password get different hashes. An attacker can't use precomputed rainbow tables, and can't crack one hash and instantly know everyone else with the same password. It doesn't make one weak password stronger. That's the job of the slow hashing function and, ultimately, of the password itself.

**7. How would you design a password policy?**
Following modern guidance: a reasonable minimum length (I default to 12), allow long passwords (up to 128+) and spaces so passphrases work, block common and breached passwords, and optionally block the user's own personal information. Avoid forced composition rules and arbitrary periodic expiry, which produce predictable variants like Summer2025! → Summer2026!. Require a change when compromise is suspected. In my tool the policy is admin-configurable through environment variables, and it's shown as POLICY PASS/FAIL separately from the strength score. `Welcome2026!` passes the default policy and is still WEAK, which shows that the two measure different things.

**8. How did you make sure the tool doesn't leak passwords?**
Several layers. It uses POST with a JSON body, never URLs, and query-string requests are rejected. Analysis happens in memory only. The analytics schema has no password column, and records are built from an explicit allow-list, so new fields can't leak in by accident. Findings contain only types and positions. Error messages are generic and never echo input. The app never logs request bodies, and a redaction filter backs that up. Responses carry `Cache-Control: no-store`. The frontend uses a `type="password"` field, textContent rendering, no local/session storage, and clears fields on page hide. Real-time typing sends `record: false`, so only an explicit button saves metadata. Then I wrote tests for each of these, for example scanning the raw SQLite bytes and the captured logs for a known synthetic password.

**9. Why does MFA matter if the password is strong?**
A strong password only protects against guessing. It doesn't help if the user is phished, if malware logs keystrokes, if a site stored it badly and got breached, or if the password was reused somewhere else. MFA adds a second factor the attacker also needs. Phishing-resistant options like passkeys and security keys even stop real-time phishing proxies. That's why every result in my tool ends with "unique password, password manager, enable MFA". Password strength is one layer, alongside rate limiting, secure hashing, lockout, session security and monitoring.

**10. What secure-coding decisions did you make, and what would you improve?**
I used `secrets` instead of `random` for generation, because Mersenne Twister is predictable. I validated input type and length (max 256) and rejected control characters. I added CSP and other security headers, rendered with textContent to avoid XSS, applied per-IP rate limiting, turned debug mode off by default because the debugger can expose request data, and logged only the exception type on errors. For improvements: a production deployment needs HTTPS with HSTS and a shared rate-limit store like Redis. I'd add a much larger dictionary, or a zxcvbn-style matcher. I'd consider an opt-in, k-anonymity breach check, where only a 5-character hash prefix leaves the machine. And I'd add CI and accessibility audits. I'd also be honest that Python can't securely wipe strings from memory. I minimize their lifetime, but I can't guarantee erasure.
