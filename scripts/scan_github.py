#!/usr/bin/env python3
"""GitHub metadata fetcher for Agent Trust Scanner."""

import json
import os
import re
import urllib.request
import urllib.error
from datetime import datetime, timezone


def parse_github_url(url: str) -> tuple:
    """Extract owner/repo from GitHub URL."""
    m = re.match(r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$', url)
    if m:
        return m.group(1), m.group(2)
    return None, None


def fetch_github_metadata(url: str) -> dict | None:
    """Fetch repo + owner metadata from GitHub API. Returns None on failure."""
    owner, repo = parse_github_url(url)
    if not owner:
        return None

    token = os.environ.get('GITHUB_TOKEN', '')
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'agent-trust-scanner'}
    if token:
        headers['Authorization'] = f'token {token}'

    def _get(path):
        req = urllib.request.Request(f'https://api.github.com{path}', headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return json.loads(r.read())
        except Exception:
            return None

    repo_data = _get(f'/repos/{owner}/{repo}')
    if not repo_data:
        return None

    owner_data = _get(f'/users/{owner}')
    contributors = _get(f'/repos/{owner}/{repo}/contributors?per_page=1&anon=true')

    now = datetime.now(timezone.utc)
    created = datetime.fromisoformat(repo_data['created_at'].replace('Z', '+00:00'))
    age_days = (now - created).days

    owner_created = None
    owner_repos = None
    owner_followers = None
    if owner_data:
        owner_created = (now - datetime.fromisoformat(owner_data['created_at'].replace('Z', '+00:00'))).days
        owner_repos = owner_data.get('public_repos', 0)
        owner_followers = owner_data.get('followers', 0)

    # Contributors count from Link header would be better, but this works
    contrib_count = None
    if contributors and isinstance(contributors, list):
        contrib_count = len(contributors)  # capped at 1 by per_page, but shows if exists

    return {
        'stars': repo_data.get('stargazers_count', 0),
        'forks': repo_data.get('forks_count', 0),
        'open_issues': repo_data.get('open_issues_count', 0),
        'age_days': age_days,
        'license': (repo_data.get('license') or {}).get('spdx_id', 'None'),
        'pushed_at': repo_data.get('pushed_at', ''),
        'owner_age_days': owner_created,
        'owner_repos': owner_repos,
        'owner_followers': owner_followers,
        'has_contributors': contrib_count is not None and contrib_count > 0,
        'description': repo_data.get('description', ''),
        'archived': repo_data.get('archived', False),
    }


def score_github(meta: dict) -> tuple:
    """Return (bonus_points, findings_list) based on GitHub metadata."""
    bonus = 0
    findings = []

    if meta['stars'] >= 100:
        bonus += 5
    elif meta['stars'] >= 10:
        bonus += 2

    if meta['age_days'] >= 365:
        bonus += 5
    elif meta['age_days'] >= 90:
        bonus += 2
    elif meta['age_days'] < 14:
        findings.append(('LOW', f"Repo is only {meta['age_days']} days old"))

    if meta.get('owner_age_days') and meta['owner_age_days'] < 30:
        findings.append(('MED', f"Owner account is only {meta['owner_age_days']} days old"))

    if meta.get('archived'):
        findings.append(('LOW', 'Repository is archived'))

    if meta['license'] == 'NOASSERTION' or meta['license'] == 'None':
        findings.append(('LOW', 'No license specified'))

    return bonus, findings


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: scan_github.py <github-url>")
        sys.exit(1)
    meta = fetch_github_metadata(sys.argv[1])
    if meta:
        print(json.dumps(meta, indent=2))
        bonus, findings = score_github(meta)
        print(f"\nBonus: +{bonus} pts")
        for sev, msg in findings:
            print(f"  [{sev}] {msg}")
    else:
        print("Could not fetch GitHub metadata.")
