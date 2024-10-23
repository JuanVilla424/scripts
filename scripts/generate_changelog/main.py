#!/usr/bin/env python3
"""
generate_changelog.py

This script automatically generates or updates the CHANGELOG.md file based on commit messages.
It processes all commit history and categorizes commits into features, fixes, etc., while
grouping non-conforming commits under a separate section.

Usage:
    python generate_changelog.py
"""

import subprocess
import re
from datetime import datetime, timezone
from typing import List, Dict, Tuple

DEBUG = False

# Define the path to the CHANGELOG.md
CHANGELOG_PATH = "CHANGELOG.md"

# Define the commit message regex pattern
# Example: feat(authentication): add OAuth2 support [minor candidate]
COMMIT_REGEX = re.compile(
    r"^(?P<type>feat|fix|docs|style|refactor|perf|test|chore)"
    r"(?:\((?P<scope>[^)]+)\))?:\s+(?P<description>.+?)\s+\[(?P<versioning_keyword>minor candidate|major "
    r"candidate|patch candidate)]$",
    re.IGNORECASE,
)

# Mapping of commit types to changelog sections
TYPE_MAPPING = {
    "feat": "### Features",
    "fix": "### Bug Fixes",
    "docs": "### Documentation",
    "style": "### Styles",
    "refactor": "### Refactors",
    "perf": "### Performance Improvements",
    "test": "### Tests",
    "chore": "### Chores",
}


def get_latest_version_from_changelog() -> str:
    """
    Retrieves the latest version from the CHANGELOG.md file.

    Returns:
        str: The latest version number or an empty string if not found.
    """
    try:
        with open(CHANGELOG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                match = re.match(r"^## \[(\d+\.\d+\.\d+)]", line)
                if match:
                    return match.group(1)
    except FileNotFoundError:
        return ""
    return ""


def get_commits_since_version(version: str) -> List[str]:
    """
    Retrieves commit messages since the specified version.

    Args:
        version (str): The version number to retrieve commits since.

    Returns:
        List[str]: A list of commit messages.
    """
    try:
        if version:
            commits = (
                subprocess.check_output(["git", "log", f"v{version}..HEAD", "--pretty=format:%s"])
                .decode()
                .split("\n")
            )
        else:
            # If no version found in CHANGELOG, get all commits
            commits = (
                subprocess.check_output(["git", "log", "--pretty=format:%s"]).decode().split("\n")
            )
        return commits
    except subprocess.CalledProcessError:
        return []


def parse_commits(commits: List[str]) -> Tuple[Dict[str, List[str]], List[str]]:
    """
    Parses commit messages and categorizes them based on type.

    Args:
        commits (List[str]): A list of commit messages.

    Returns:
        Tuple[Dict[str, List[str]], List[str]]: A dictionary categorizing commits and a list of non-conforming commits.
    """
    changelog = {section: [] for section in TYPE_MAPPING.values()}
    non_conforming_commits = []

    for commit in commits:
        match = COMMIT_REGEX.match(commit)
        if match:
            commit_type = match.group("type").lower()
            scope = match.group("scope")
            description = match.group("description").strip()
            versioning_keyword = match.group("versioning_keyword").lower()

            section = TYPE_MAPPING.get(commit_type)
            if section:
                if scope:
                    entry = f"- **{scope}**: {description} (`{versioning_keyword}`)"
                else:
                    entry = f"- {description} (`{versioning_keyword}`)"
                changelog[section].append(entry)
            else:
                non_conforming_commits.append(commit)
        else:
            non_conforming_commits.append(commit)

    # Remove empty sections
    changelog = {k: v for k, v in changelog.items() if v}
    return changelog, non_conforming_commits


def generate_changelog_entry(
    version: str, changelog: Dict[str, List[str]], non_conforming: List[str]
) -> str:
    """
    Generates a changelog entry for a specific version.

    Args:
        version (str): The version number.
        changelog (Dict[str, List[str]]): The categorized changelog entries.
        non_conforming (List[str]): List of non-conforming commit messages.

    Returns:
        str: The formatted changelog entry.
    """
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    entry = f"## [{version}] - {date}\n\n"
    for section, items in changelog.items():
        entry += f"{section}\n"
        for item in items:
            entry += f"{item}\n"
        entry += "\n"

    if non_conforming:
        entry += "### Other Changes\n"
        for commit in non_conforming:
            entry += f"- {commit}\n"
        entry += "\n"

    return entry


def update_changelog(version: str, new_entry: str):
    """
    Updates the CHANGELOG.md file by prepending the new entry.

    Args:
        version (str): The version number.
        new_entry (str): The new changelog entry to add.
    """
    if DEBUG:
        print(f"Updating version... {version}")
    try:
        with open(CHANGELOG_PATH, "r", encoding="utf-8") as f:
            existing_content = f.read()
    except FileNotFoundError:
        existing_content = ""

    with open(CHANGELOG_PATH, "w", encoding="utf-8") as f:
        f.write(new_entry + "\n" + existing_content)


def get_next_version(latest_version: str, version_bump: str) -> str:
    """
    Calculates the next version based on the current version and the type of version bump.

    Args:
        latest_version (str): The latest version number.
        version_bump (str): The type of version bump ('major', 'minor', 'patch').

    Returns:
        str: The next version string.
    """
    if not latest_version:
        # Default initial version if no changelog exists
        return "1.0.0"

    major, minor, patch = map(int, latest_version.split("."))

    if version_bump == "major":
        major += 1
        minor = 0
        patch = 0
    elif version_bump == "minor":
        minor += 1
        patch = 0
    elif version_bump == "patch":
        patch += 1

    return f"{major}.{minor}.{patch}"


def get_version_bump(commits: List[str]) -> str:
    """
    Determines the type of version bump based on commit messages.

    Args:
        commits (List[str]): A list of commit messages.

    Returns:
        str: The type of version bump ('major', 'minor', 'patch') or an empty string if none.
    """
    # Priority: major > minor > patch
    bump = ""

    for commit in commits:
        match = COMMIT_REGEX.match(commit)
        if match:
            keyword = match.group("versioning_keyword").lower()
            if keyword == "major candidate":
                bump = "major"
            elif keyword == "minor candidate" and bump != "major":
                bump = "minor"
            elif keyword == "patch candidate" and not bump:
                bump = "patch"

    return bump


def main():
    """
    Main function to generate or update the CHANGELOG.md.
    """
    latest_version = get_latest_version_from_changelog()
    print(f"Latest version in CHANGELOG.md: {latest_version}")
    commits = get_commits_since_version(latest_version)
    if not commits:
        print("No new commits to include in the changelog.")
        return

    changelog, non_conforming = parse_commits(commits)
    if not changelog and not non_conforming:
        print("No valid commits found for changelog generation.")
        return

    # Determine the next version based on the highest priority keyword
    version_bump = get_version_bump(commits)

    if not version_bump and non_conforming:
        # Assign a patch bump if there are non-conforming commits but no version bump keywords
        version_bump = "patch"

    if not version_bump and not non_conforming:
        print("No versioning keyword found in commits.")
        return

    # Get the next version
    next_version = get_next_version(latest_version, version_bump)
    print(f"Bumping version: {version_bump} to {next_version}")

    # Generate changelog entry
    changelog_entry = generate_changelog_entry(next_version, changelog, non_conforming)

    # Update CHANGELOG.md
    update_changelog(next_version, changelog_entry)
    print(f"CHANGELOG.md updated with version {next_version}.")


if __name__ == "__main__":
    main()
