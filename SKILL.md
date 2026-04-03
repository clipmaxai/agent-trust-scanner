# Agent Trust Scanner

Scan agent skills for security risks — prompt injection, credential theft, malicious code patterns, and supply chain vulnerabilities.

## Usage

```
python3 scripts/scan.py <path-or-github-url>
```

Accepts a local skill directory path or a GitHub repository URL. Produces a trust score (0-100) with detailed findings.

## When to Use

- Before installing a third-party skill
- When auditing existing skills for security issues
- When reviewing a skill's codebase for prompt injection or malicious patterns

## Examples

```bash
# Scan a local skill
python3 ~/.openclaw/workspace/skills/agent-trust-scanner/scripts/scan.py ./skills/some-skill/

# Scan a GitHub repo
python3 ~/.openclaw/workspace/skills/agent-trust-scanner/scripts/scan.py https://github.com/user/agent-skill

# Scan all skills in a directory
for d in ./skills/*/; do python3 ~/.openclaw/workspace/skills/agent-trust-scanner/scripts/scan.py "$d"; echo; done
```

## Output

Returns a formatted report with:
- Overall trust score (0-100)
- Categorized findings: Prompt Injection, Code Analysis, Dependencies, Network
- GitHub metadata (when URL provided)
- Verdict: LOW RISK ✅ / MODERATE RISK ⚠️ / HIGH RISK 🔴 / CRITICAL 🚫

## Constraints

- Python 3 stdlib only — no pip dependencies
- GitHub checks require network (graceful degradation)
- Scans: .md, .py, .sh, .js, .ts, .json, .yaml, .yml files
- Ignores binary files and images
