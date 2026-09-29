# Local Execution — Step by Step

Commands are shown for **Windows PowerShell**, with macOS/Linux differences noted. You need Python 3.10 or newer (`python --version`).

### Step 1: Create or clone the project folder
```powershell
git clone https://github.com/SNischayPrasad/Password-Strength-Analyzer-Security-Tool.git
cd Password-Strength-Analyzer-Security-Tool
```
(Or just `cd` into the folder that contains `backend/`, `frontend/` and `data/`.)

### Step 2: Create a virtual environment
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```
macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`.
If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use `.venv\Scripts\activate.bat` from cmd.

### Step 3: Install dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Start the backend
```powershell
python -m backend.app
```
You should see `Password Strength Analyzer running at http://127.0.0.1:5000`.

### Step 5: Start the frontend
Nothing to do. Flask serves the HTML/CSS/JS from `frontend/` on the same port, which also avoids CORS configuration.

### Step 6: Open the browser
Go to **http://127.0.0.1:5000**.

### Step 7: Analyze synthetic test passwords
Type these one at a time. The result updates as you type.

| Input | Expected | Why |
|---|---|---|
| `123456` | VERY WEAK | Common, short, numeric, sequential |
| `Password123!` | WEAK (project calibration; could be Moderate under other weights) | Four character types, but a common word + "123" + "!" |
| `aaaaaaaaaaaaaaaa` | WEAK | Long but completely repetitive |
| `qwerty2026!` | WEAK | Keyboard walk + year |
| A generated 20-character password (Step 9) | VERY STRONG | Random from ~86 symbols ≈ 128 bits, no patterns |

Then expand **"Optional: check against personal details"**, enter the demo first name `Rahul`, and type `Rahul@123`. You'll get a *Personal information* finding.

### Step 8: View recommendations
Read the **Suggestions** panel (specific to each finding), the **Findings** list, the **Pattern map**, and *How this score was calculated* under Measurements.

### Step 9: Generate a secure demo password
Scroll to **Let a machine choose** → *Generate password* → *Check this password*. The generated value is used for the demonstration only. Don't reuse it.

### Step 10: View the aggregate dashboard
Optionally click **Add result to anonymous stats** for a few analyses, or load synthetic data:
```powershell
python scripts/seed_demo_data.py --reset
```
Then open **http://127.0.0.1:5000/dashboard**.

### Extras
```powershell
python -m pytest -v              # run all 73 tests
python scripts/analyze_cli.py    # command-line analyzer (hidden input)
python demos/hashing_demo.py     # Argon2id hashing demonstration
```

Stop the server with `Ctrl + C`.
