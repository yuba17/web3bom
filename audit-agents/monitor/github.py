"""GitHubMonitor for monitor package."""
import time
from datetime import datetime, timezone

import requests

from monitor.config import GITHUB_TOKEN, GITHUB_WATCHLIST, console, logger
from monitor.state import Alert, State
from monitor.notifier import Notifier


class GitHubMonitor:
    """
    Watch repos for new commits after their last audit date.

    Uses GitHub REST API:
      GET /repos/{owner}/{repo}/commits
        ?sha={branch}
        &since={last_audit_date}
        &per_page=30

    Rate limits:
      - Without token: 60 requests/hour
      - With token: 5,000 requests/hour

    Recommended cron: every 30 minutes (48 calls/day per repo = fine)
    """

    API_BASE = "https://api.github.com"

    def __init__(self, state: State, notifier: Notifier):
        self.state = state
        self.notifier = notifier
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "BountyMonitor/1.0",
        }
        if GITHUB_TOKEN:
            self.headers["Authorization"] = f"token {GITHUB_TOKEN}"

    def check_all(self, notify_channels: list[str]) -> list[Alert]:
        """Check all watched repos for new commits."""
        alerts = []
        for repo, config in GITHUB_WATCHLIST.items():
            try:
                new_alerts = self._check_repo(repo, config, notify_channels)
                alerts.extend(new_alerts)
                time.sleep(1)  # Rate limit courtesy
            except Exception as e:
                logger.error(f"GitHub check failed for {repo}: {e}")
        return alerts

    def _check_repo(self, repo: str, config: dict, notify_channels: list[str]) -> list[Alert]:
        """Check a single repo for new commits since last audit."""
        branch = config.get("branch", "main")
        last_audit = config.get("last_audit_date", "2024-01-01")
        paths_of_interest = config.get("paths_of_interest", [])
        max_bounty = config.get("max_bounty", 0)
        bounty_url = config.get("bounty_url", "")

        last_seen_sha = self.state.get("github_last_sha", repo)

        # Fetch recent commits since audit date
        url = f"{self.API_BASE}/repos/{repo}/commits"
        params = {
            "sha": branch,
            "since": f"{last_audit}T00:00:00Z",
            "per_page": 30,
        }

        resp = requests.get(url, headers=self.headers, params=params, timeout=30)
        if resp.status_code == 404:
            logger.warning(f"Repo not found: {repo}")
            return []
        if resp.status_code == 403:
            logger.warning(f"GitHub rate limited. Set GITHUB_TOKEN env var.")
            return []
        resp.raise_for_status()

        commits = resp.json()
        if not commits:
            return []

        latest_sha = commits[0]["sha"]

        # First run: just save the latest SHA, don't alert
        if last_seen_sha is None:
            self.state.set("github_last_sha", repo, latest_sha)
            console.print(f"  [dim]{repo}: initialized at {latest_sha[:8]}[/dim]")
            return []

        # Find new commits since last seen
        new_commits = []
        for commit in commits:
            if commit["sha"] == last_seen_sha:
                break
            new_commits.append(commit)

        if not new_commits:
            return []

        # Update state
        self.state.set("github_last_sha", repo, latest_sha)

        # Filter by paths of interest if specified
        relevant_commits = new_commits
        if paths_of_interest:
            relevant_commits = self._filter_by_paths(repo, new_commits, paths_of_interest)

        if not relevant_commits:
            return []

        # Build alert
        commit_summaries = []
        for c in relevant_commits[:10]:
            msg = c.get("commit", {}).get("message", "").split("\n")[0][:80]
            sha = c["sha"][:8]
            commit_summaries.append(f"  {sha}: {msg}")

        alert = Alert(
            id=f"github:{repo}:{latest_sha[:8]}",
            alert_type="github_commit",
            target=repo,
            title=f"{len(relevant_commits)} new commit(s) in {repo}",
            details=(
                f"{len(relevant_commits)} commits after last audit ({last_audit}).\n"
                f"Branch: {branch}\n"
                f"Latest commits:\n" + "\n".join(commit_summaries)
            ),
            url=f"https://github.com/{repo}/commits/{branch}",
            bounty_url=bounty_url,
            max_bounty=max_bounty,
            priority_score=self._score_github_alert(relevant_commits, config),
            timestamp=datetime.now(timezone.utc).isoformat(),
            raw_data={"commits": [c["sha"] for c in relevant_commits]},
        )

        self.notifier.send(alert, notify_channels)
        return [alert]

    def _filter_by_paths(self, repo: str, commits: list, paths: list) -> list:
        """Filter commits to only those touching paths of interest."""
        relevant = []
        for commit in commits[:5]:  # Check up to 5 commits (API calls)
            sha = commit["sha"]
            url = f"{self.API_BASE}/repos/{repo}/commits/{sha}"
            try:
                resp = requests.get(url, headers=self.headers, timeout=15)
                if resp.status_code != 200:
                    relevant.append(commit)  # Can't check, assume relevant
                    continue
                data = resp.json()
                files = data.get("files", [])
                for f in files:
                    filename = f.get("filename", "")
                    if any(filename.startswith(p) for p in paths):
                        relevant.append(commit)
                        break
                time.sleep(0.5)  # Rate limit
            except Exception:
                relevant.append(commit)  # Can't check, assume relevant
        return relevant

    def _score_github_alert(self, commits: list, config: dict) -> float:
        """Score the priority of a GitHub commit alert."""
        score = 30.0  # base

        # More commits = more changes = higher priority
        n = len(commits)
        if n >= 20:
            score += 30
        elif n >= 10:
            score += 20
        elif n >= 5:
            score += 15
        elif n >= 2:
            score += 10

        # Higher bounty = higher priority
        bounty = config.get("max_bounty", 0)
        if bounty >= 5_000_000:
            score += 30
        elif bounty >= 1_000_000:
            score += 20
        elif bounty >= 500_000:
            score += 15
        elif bounty >= 100_000:
            score += 10

        # Check commit messages for interesting keywords
        interesting_keywords = [
            "fix", "bug", "vulnerability", "security", "critical",
            "overflow", "underflow", "reentrancy", "access control",
            "oracle", "price", "liquidation", "flash", "migration",
            "upgrade", "emergency", "pause", "unpause", "hotfix",
        ]
        for commit in commits:
            msg = commit.get("commit", {}).get("message", "").lower()
            if any(kw in msg for kw in interesting_keywords):
                score += 10
                break

        return min(100, score)
