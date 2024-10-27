#!/usr/bin/env python3
"""
commit_msg_version_bump.py

A script to bump the version in pyproject.toml based on commit message keywords.
Handles major, minor, and patch releases. Additionally, it adds icons to commit messages
depending on their type and ensures that changes are committed in a single step.

Usage:
    commit_msg_version_bump.py [--log-level {INFO,DEBUG}]
"""

import argparse
import logging
import re
import subprocess
import sys
from logging.handlers import RotatingFileHandler
from typing import List, Optional

import toml

# Mapping of commit types to changelog sections and icons
TYPE_MAPPING = {
    "feat": {"section": "### Features", "icon": "✨"},
    "fix": {"section": "### Bug Fixes", "icon": "🐛"},
    "docs": {"section": "### Documentation", "icon": "📝"},
    "style": {"section": "### Styles", "icon": "💄"},
    "refactor": {"section": "### Refactors", "icon": "♻️"},
    "perf": {"section": "### Performance Improvements", "icon": "⚡️"},
    "test": {"section": "### Tests", "icon": "✅"},
    "chore": {"section": "### Chores", "icon": "🔧"},
}

# Mapping of commit types to version bump parts
VERSION_BUMP_MAPPING = {
    "feat": "minor",
    "fix": "patch",
    "docs": "patch",
    "style": "patch",
    "refactor": "patch",
    "perf": "patch",
    "test": "patch",
    "chore": "patch",
}

# Regular expressions for detecting commit types and versioning keywords
COMMIT_TYPE_REGEX = re.compile(
    r"^(?P<type>feat|fix|docs|style|refactor|perf|test|chore)", re.IGNORECASE
)
VERSION_KEYWORD_REGEX = re.compile(
    r"\[(?P<keyword>major candidate|minor candidate|patch candidate)]$", re.IGNORECASE
)

# Initialize the logger
logger = logging.getLogger(__name__)


def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Bump the version in pyproject.toml based on commit message keywords. "
            "Adds icons to commit messages depending on their type."
        )
    )
    parser.add_argument(
        "--log-level",
        choices=["INFO", "DEBUG"],
        default="INFO",
        help="Set the logging level. Default is INFO.",
    )
    return parser.parse_args()


def configure_logger(log_level: str) -> None:
    """
    Configures logging for the script.

    Args:
        log_level (str): Logging level as a string (e.g., 'INFO', 'DEBUG').
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    logger.setLevel(numeric_level)

    # Set up log rotation: max size 5MB, keep 5 backup files
    file_handler = RotatingFileHandler(
        "commit_msg_version.log", maxBytes=5 * 1024 * 1024, backupCount=5
    )
    console_handler = logging.StreamHandler()

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def get_pushed_refs() -> List[str]:
    """
    Retrieves the list of refs being pushed.

    Returns:
        List[str]: List of refs being pushed.
    """
    refs = []
    try:
        # Read from stdin the refs being pushed
        for line in sys.stdin:
            parts = line.strip().split()
            if len(parts) >= 2:
                local_ref, local_sha = parts[0], parts[1]
                refs.append(local_ref)
        logging.debug(f"Refs being pushed: {refs}")
        return refs
    except Exception as e:
        logging.error(f"Error reading refs from stdin: {e}")
        sys.exit(1)


def get_upstream_branch() -> Optional[str]:
    """
    Retrieves the upstream branch for the current branch.

    Returns:
        Optional[str]: The upstream branch name or None if not found.
    """
    try:
        upstream = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        logger.debug(f"Upstream branch: {upstream}")
        return upstream
    except subprocess.CalledProcessError as e:
        logger.error(f"Error retrieving upstream branch: {e.stderr}")
        return None


def get_commits_being_pushed(local_ref: str, remote_ref: str) -> List[str]:
    """
    Retrieves the list of commit hashes being pushed for a given ref.

    Args:
        local_ref (str): The local ref being pushed.
        remote_ref (str): The remote ref being pushed to.

    Returns:
        List[str]: List of commit hashes being pushed.
    """
    try:
        commits = (
            subprocess.run(
                ["git", "rev-list", "--no-merges", f"{remote_ref}..{local_ref}"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            .stdout.strip()
            .split("\n")
        )
        commits = [commit for commit in commits if commit]
        logger.debug(f"Commits being pushed for {local_ref}..{remote_ref}: {commits}")
        return commits
    except subprocess.CalledProcessError as e:
        logger.error(f"Error retrieving commits for {local_ref}..{remote_ref}: {e.stderr}")
        sys.exit(1)


def read_commit_messages(commits: List[str]) -> List[str]:
    """
    Reads commit messages for the given list of commits.

    Args:
        commits (List[str]): List of commit hashes.

    Returns:
        List[str]: List of commit messages.
    """
    commit_messages = []
    for commit in commits:
        try:
            message = subprocess.run(
                ["git", "log", "--format=%B", "-n", "1", commit],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            logger.debug(f"Commit {commit}: {message}")
            commit_messages.append(message)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error reading commit {commit}: {e.stderr}")
            sys.exit(1)
    return commit_messages


def add_icon_to_commit_message(commit_msg: str) -> str:
    """
    Adds an icon to the commit message based on its type.

    Args:
        commit_msg (str): The original commit message.

    Returns:
        str: The commit message with the icon prepended.
    """
    match = COMMIT_TYPE_REGEX.match(commit_msg)
    if match:
        commit_type = match.group("type").lower()
        icon = TYPE_MAPPING.get(commit_type, {}).get("icon", "")
        if icon:
            # Avoid adding multiple icons
            if not commit_msg.startswith(icon):
                new_commit_msg = f"{icon} {commit_msg}"
                logger.debug(f"Updated commit message with icon: {new_commit_msg}")
                return new_commit_msg
    logger.debug("No matching commit type found or icon already present.")
    return commit_msg


def determine_version_bump(commit_msg: str) -> Optional[str]:
    """
    Determines the version bump part based on the commit message.

    Args:
        commit_msg (str): The commit message.

    Returns:
        Optional[str]: The version part to bump ('major', 'minor', 'patch') or None.
    """
    match = VERSION_KEYWORD_REGEX.search(commit_msg)
    if match:
        keyword = match.group("keyword").lower()
        if "major" in keyword:
            return "major"
        elif "minor" in keyword:
            return "minor"
        elif "patch" in keyword:
            return "patch"
    else:
        # Fallback based on commit type
        type_match = COMMIT_TYPE_REGEX.match(commit_msg)
        if type_match:
            commit_type = type_match.group("type").lower()
            return VERSION_BUMP_MAPPING.get(commit_type)
    return None


def bump_version(part: str) -> None:
    """
    Bumps the specified part of the version using bump2version.

    Args:
        part (str): The part of the version to bump ('major', 'minor', 'patch').

    Raises:
        subprocess.CalledProcessError: If bump2version fails.
    """
    try:
        subprocess.run(["bump2version", part], check=True)
        logger.info(f"Successfully bumped the {part} version.")
    except subprocess.CalledProcessError as error:
        logger.error(f"Failed to bump the {part} version: {error}")
        sys.exit(1)


def get_new_version(pyproject_path: str = "pyproject.toml") -> str:
    """
    Retrieves the new version from pyproject.toml.

    Args:
        pyproject_path (str): Path to the pyproject.toml file.

    Returns:
        str: The new version string.

    Raises:
        SystemExit: If the version cannot be retrieved.
    """
    try:
        with open(pyproject_path, "r", encoding="utf-8") as file:
            data = toml.load(file)
        version = data["tool"]["poetry"]["version"]
        logger.debug(f"New version retrieved: {version}")
        return version
    except (FileNotFoundError, KeyError, ValueError, toml.TomlDecodeError) as e:
        logger.error(f"Error retrieving the version from {pyproject_path}: {e}")
        sys.exit(1)


def stage_changes(pyproject_path: str = "pyproject.toml") -> None:
    """
    Stages the specified file for commit.

    Args:
        pyproject_path (str): Path to the file to stage.
    """
    try:
        subprocess.run(["git", "add", pyproject_path], check=True)
        logger.debug(f"Staged {pyproject_path} for commit.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to stage {pyproject_path}: {e}")
        sys.exit(1)


def amend_commit(new_commit_msg: str) -> None:
    """
    Amends the current commit with the new commit message.

    Args:
        new_commit_msg (str): The new commit message.

    Raises:
        subprocess.CalledProcessError: If git amend fails.
    """
    try:
        # Amend the commit with the new commit message
        subprocess.run(["git", "commit", "--amend", "-m", new_commit_msg], check=True)
        logger.info("Successfully amended the commit with the new version bump.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to amend the commit: {e}")
        sys.exit(1)


def main() -> None:
    """
    Main function to parse commit messages and perform version bumping and commit message enhancement.
    """
    args = parse_arguments()
    configure_logger(args.log_level)

    # Retrieve refs being pushed from stdin
    pushed_refs = get_pushed_refs()
    if not pushed_refs:
        logger.info("No refs being pushed.")
        return

    upstream_ref = get_upstream_branch()
    if not upstream_ref:
        logger.error("No upstream branch found. Aborting.")
        sys.exit(1)

    for local_ref in pushed_refs:
        commits = get_commits_being_pushed(local_ref, upstream_ref)
        if not commits:
            logger.info(f"No new commits to process for {local_ref}.")
            continue

        commit_messages = read_commit_messages(commits)

        for commit_msg in commit_messages:
            updated_commit_msg = add_icon_to_commit_message(commit_msg)
            version_bump_part = determine_version_bump(commit_msg)

            if version_bump_part:
                logger.info(f"Version bump detected: {version_bump_part}")
                bump_version(version_bump_part)
                # new_version = get_new_version()

                # Stage the updated pyproject.toml
                stage_changes()

                # Amend the latest commit with the updated commit message
                amend_commit(updated_commit_msg)

                # After bumping and amending, stop processing further commits to avoid multiple bumps
                break
            else:
                logger.info("No version bump detected in commit message.")


if __name__ == "__main__":
    main()
