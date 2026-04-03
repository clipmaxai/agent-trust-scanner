#!/usr/bin/env python3
"""Agent Trust Scanner — scans skill directories for security risks."""

import argparse, json, os, re, sys
from pathlib import Path

SAFE_DOMAINS = {
    "github.com", "pypi.org", "npmjs.com", "googleapis.com", "wttr.in", "api.github.com",
    "api.openweathermap.org", "hacker-news.firebaseio.com", "news.ycombinator.com",
    "www.producthunt.com", "api.producthunt.com", "api.coingecko.com", "api.llama.fi",
    "www.youtube.com", "youtube.com", "api.twitter.com", "x.com",
    "raw.githubusercontent.com", "registry.npmjs.org", "huggingface.co",
    "api.openai.com", "api.anthropic.com",
    "cdn.jsdelivr.net", "unpkg.com", "fonts.googleapis.com", "cdnjs.cloudflare.com",
}
SEV_SCORES = {"HIGH": -15, "MED": -8, "LOW": -3}
SCAN_EXTS = {".md", ".py", ".sh", ".js", ".ts", ".json", ".yaml", ".yml"}
CODE_EXTS = {".py", ".sh", ".js", ".ts"}

DOMAIN_RE = re.compile(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})')

# --- Prompt injection patterns (for .md files) ---
PI_PATTERNS = [
    ("HIGH", re.compile(r'~/\.ssh|~/\.env|~/\.openclaw/(?:secrets|workspace/\.secrets)|/etc/passwd', re.I), "References sensitive paths"),
    ("HIGH", re.compile(r'(?:credentials|api.?keys?|tokens?|passwords?)\b', re.I), "References credentials/secrets"),
    ("HIGH", re.compile(r'ignore\s+(?:all\s+)?previous\s+(?:instructions|safety)', re.I), "Prompt override attempt"),
    ("HIGH", re.compile(r'system\s+prompt|you\s+are\s+now|forget\s+your\s+rules', re.I), "Identity manipulation"),
    ("HIGH", re.compile(r'(?:curl|wget|fetch)\s+.*https?://\S+.*(?:\||\$\()', re.I), "Data exfiltration via curl/wget"),
    ("MED", re.compile(r'(?:modify|edit|change|update|write)\s+.*(?:AGENTS\.md|SOUL\.md|openclaw\.json|\.claude/)', re.I), "Modifies agent config files"),
    ("MED", re.compile(r'[A-Za-z0-9+/]{50,}={0,2}'), "Large base64 block"),
    ("HIGH", re.compile(r'[\u200b\u200c\u200d\ufeff\u202e]'), "Zero-width Unicode characters"),
    ("HIGH", re.compile(r'<!--.*?-->', re.S), "HTML comment (potential hidden instructions)"),
    ("MED", re.compile(r'\b(?:npx|pip\s+install|npm\s+install)\b', re.I), "Chain loading external packages"),
    ("MED", re.compile(r'summarize\s+your\s+context|show\s+system\s+prompt|repeat\s+(?:your\s+)?instructions', re.I), "Context extraction attempt"),
]

# --- Code analysis patterns ---
CODE_PATTERNS_PY = [
    ("HIGH", re.compile(r'\beval\s*\([^"\')\s]'), "eval() with non-literal args"),
    ("HIGH", re.compile(r'\bexec\s*\([^"\')\s]'), "exec() with non-literal args"),
    ("HIGH", re.compile(r'\bcompile\s*\('), "compile() usage"),
    ("HIGH", re.compile(r'subprocess\.\w+\(.*shell\s*=\s*True', re.S), "subprocess with shell=True"),
    ("HIGH", re.compile(r'\bos\.system\s*\('), "os.system() usage"),
    ("HIGH", re.compile(r'\bos\.popen\s*\('), "os.popen() usage"),
    ("MED", re.compile(r'os\.environ|os\.getenv'), "Environment variable access"),
    ("MED", re.compile(r'open\s*\(.*(?:\.\./|~/\.ssh|~/\.env|/etc/)', re.I), "File access to sensitive paths"),
    ("LOW", re.compile(r'\b(?:urllib|requests|http\.client)\b'), "Network library import"),
    ("HIGH", re.compile(r'AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]+|gho_[a-zA-Z0-9]+|sk-[a-zA-Z0-9]{20,}'), "Credential pattern"),
    ("HIGH", re.compile(r"''\s*\.join\s*\(\s*chr\s*\("), "chr()+join obfuscation"),
    ("MED", re.compile(r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}'), "Hex string obfuscation"),
]

CODE_PATTERNS_JS = [
    ("HIGH", re.compile(r'\beval\s*\('), "eval() usage"),
    ("HIGH", re.compile(r'\bFunction\s*\('), "Function() constructor"),
    ("MED", re.compile(r'process\.env'), "Environment variable access"),
    ("MED", re.compile(r'\b(?:fetch|axios|require\s*\(\s*[\'"]https?)', re.I), "Network access"),
    ("HIGH", re.compile(r'\b(?:atob|btoa)\s*\('), "Base64 obfuscation"),
    ("HIGH", re.compile(r'AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]+|gho_[a-zA-Z0-9]+|sk-[a-zA-Z0-9]{20,}'), "Credential pattern"),
]

CODE_PATTERNS_SH = [
    ("HIGH", re.compile(r'curl\s+.*\|\s*(?:bash|sh)', re.I), "Piping curl to shell"),
    ("HIGH", re.compile(r'(?:curl|wget)\s+.*https?://\S+', re.I), "Network request"),
    ("HIGH", re.compile(r'/etc/passwd|~/\.ssh', re.I), "Sensitive file access"),
    ("MED", re.compile(r'\beval\b'), "eval usage in shell"),
    ("HIGH", re.compile(r'base64'), "Base64 encoding (possible exfil)"),
]


def scan_file(filepath, findings, domains):
    p = Path(filepath)
    ext = p.suffix.lower()
    if ext not in SCAN_EXTS:
        return
    try:
        content = p.read_text(errors='replace')
    except Exception:
        return
    lines = content.split('\n')
    rel = str(p)

    # Extract domains from all files
    for i, line in enumerate(lines, 1):
        for m in DOMAIN_RE.finditer(line):
            domains.add(m.group(1))

    if ext == '.md':
        for sev, pat, desc in PI_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pat.search(line):
                    findings.append(("PROMPT_INJECTION", sev, rel, i, desc))
    elif ext in CODE_EXTS:
        if ext == '.py':
            patterns = CODE_PATTERNS_PY
        elif ext in ('.js', '.ts'):
            patterns = CODE_PATTERNS_JS
        elif ext == '.sh':
            patterns = CODE_PATTERNS_SH
        else:
            patterns = []
        for sev, pat, desc in patterns:
            for i, line in enumerate(lines, 1):
                if pat.search(line):
                    findings.append(("CODE_ANALYSIS", sev, rel, i, desc))

    # Check for env var specifics in code
    if ext == '.py':
        for i, line in enumerate(lines, 1):
            m = re.search(r'os\.environ\.get\s*\(\s*[\'"](\w+)', line)
            if m:
                findings.append(("CODE_ANALYSIS", "MED", rel, i, f"Reads env var: {m.group(1)}"))
            m = re.search(r'os\.getenv\s*\(\s*[\'"](\w+)', line)
            if m:
                findings.append(("CODE_ANALYSIS", "MED", rel, i, f"Reads env var: {m.group(1)}"))


def scan_deps(target, findings):
    req = Path(target) / 'requirements.txt'
    if req.exists():
        deps = [l.strip().split('==')[0].split('>=')[0].split('[')[0] for l in req.read_text().splitlines() if l.strip() and not l.startswith('#')]
        if len(deps) > 20:
            findings.append(("DEPENDENCIES", "MED", str(req), 0, f"High dependency count: {len(deps)}"))
        for d in deps:
            if len(d) < 3:
                findings.append(("DEPENDENCIES", "HIGH", str(req), 0, f"Suspiciously short package name: '{d}' (typosquat risk)"))

    pkg = Path(target) / 'package.json'
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
            all_deps = list((data.get('dependencies') or {}).keys()) + list((data.get('devDependencies') or {}).keys())
            if len(all_deps) > 20:
                findings.append(("DEPENDENCIES", "MED", str(pkg), 0, f"High dependency count: {len(all_deps)}"))
            for d in all_deps:
                if len(d) < 3:
                    findings.append(("DEPENDENCIES", "HIGH", str(pkg), 0, f"Suspiciously short package name: '{d}'"))
        except Exception:
            pass


def scan_directory(target, github_url=None):
    target = Path(target).resolve()
    findings = []
    domains = set()

    for root, dirs, files in os.walk(target):
        for f in files:
            fp = Path(root) / f
            scan_file(fp, findings, domains)

    scan_deps(target, findings)

    # Network findings
    unsafe = domains - SAFE_DOMAINS
    for d in sorted(domains & SAFE_DOMAINS):
        findings.append(("NETWORK", "LOW", "", 0, f"Known-safe domain: {d}"))
    for d in sorted(unsafe):
        findings.append(("NETWORK", "HIGH", "", 0, f"Unknown external domain: {d}"))

    # Scoring
    score = 100
    # Deduplicate for scoring
    seen = set()
    unique_findings = []
    for f in findings:
        key = (f[0], f[1], f[2], f[3], f[4])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    findings = unique_findings

    for cat, sev, *_ in findings:
        score += SEV_SCORES.get(sev, 0)

    # GitHub bonus
    if github_url:
        try:
            script_dir = Path(__file__).parent
            sys.path.insert(0, str(script_dir))
            from scan_github import scan_github_repo
            gh_result = scan_github_repo(github_url)
            score += gh_result.get('bonus', 0)
            for f in gh_result.get('findings', []):
                findings.append(f)
        except Exception:
            pass

    score = max(0, min(100, score))

    if score >= 80:
        verdict = "LOW RISK ✅"
    elif score >= 60:
        verdict = "MODERATE RISK ⚠️"
    elif score >= 30:
        verdict = "HIGH RISK 🔴"
    else:
        verdict = "CRITICAL 🚫"

    return {"target": str(target), "score": score, "verdict": verdict, "findings": findings}


def format_output(result, quiet=False):
    lines = []
    lines.append("🔍 Agent Trust Scanner — Results")
    lines.append("═══════════════════════════════════")
    lines.append("")
    lines.append(f"Target: {result['target']}")
    lines.append(f"Score: {result['score']}/100 ({result['verdict']})")
    lines.append("")

    cats = {}
    for f in result['findings']:
        cats.setdefault(f[0], []).append(f)

    icons = {"PROMPT_INJECTION": "⚠️", "CODE_ANALYSIS": "🔒", "DEPENDENCIES": "📦", "NETWORK": "🌐"}
    for cat in ["PROMPT_INJECTION", "CODE_ANALYSIS", "DEPENDENCIES", "NETWORK"]:
        items = cats.get(cat, [])
        if items or not quiet:
            lines.append(f"{icons.get(cat, '•')} {cat.replace('_', ' ')} ({len(items)} findings)")
            for _, sev, filepath, lineno, desc in items:
                if filepath and lineno:
                    lines.append(f"  [{sev}] {filepath}:{lineno} — {desc}")
                else:
                    lines.append(f"  [{sev}] {desc}")
            lines.append("")

    lines.append("═══════════════════════════════════")
    lines.append(f"Verdict: {result['verdict']}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Agent Trust Scanner")
    parser.add_argument("path", help="Skill directory to scan")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--quiet", action="store_true", help="Hide empty categories")
    parser.add_argument("--github", help="GitHub repo URL for bonus scoring")
    args = parser.parse_args()

    if not Path(args.path).is_dir():
        print(f"Error: {args.path} is not a directory", file=sys.stderr)
        sys.exit(1)

    result = scan_directory(args.path, args.github)

    if args.json:
        out = {"target": result["target"], "score": result["score"], "verdict": result["verdict"],
               "findings": [{"category": f[0], "severity": f[1], "file": f[2], "line": f[3], "description": f[4]} for f in result["findings"]]}
        print(json.dumps(out, indent=2))
    else:
        print(format_output(result, args.quiet))


if __name__ == "__main__":
    main()
