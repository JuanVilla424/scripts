#!/usr/bin/env python3
"""
commit_msg_version_bump.py

A script to bump the version in pyproject.toml based on commit message keywords.
Handles major, minor, and patch releases. Additionally, it adds icons to commit messages
depending on their type and ensures that changes are committed in a single step.

Usage:
    commit_msg_version_bump.py <commit_msg_file> [--log-level {INFO,DEBUG}]
"""

import argparse
import logging
import re
import subprocess
import sys
from typing import Optional

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
COMMIT_TYPE_REGEX = re.compile(r"^(?P<type>feat|fix|docs|style|refactor|perf|test|chore)")
VERSION_KEYWORD_REGEX = re.compile(
    r"\[(?P<keyword>major candidate|minor candidate|patch candidate)]$", re.IGNORECASE
)


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
        "commit_msg_file",
        type=str,
        help="Path to the commit message file.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
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
        print(f"Invalid log level: {log_level}")
        sys.exit(1)

    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def read_commit_message(commit_msg_file: str) -> str:
    """
    Reads the commit message from the given file.

    Args:
        commit_msg_file (str): Path to the commit message file.

    Returns:
        str: The commit message content.
    """
    try:
        with open(commit_msg_file, "r", encoding="utf-8") as file:
            commit_msg = file.read().strip()
            logging.debug(f"Original commit message: {commit_msg}")
            return commit_msg
    except FileNotFoundError:
        logging.error(f"Commit message file not found: {commit_msg_file}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading commit message file: {e}")
        sys.exit(1)


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
                logging.debug(f"Updated commit message with icon: {new_commit_msg}")
                return new_commit_msg
    logging.debug("No matching commit type found or icon already present.")
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
        logging.info(f"Successfully bumped the {part} version.")
    except subprocess.CalledProcessError as error:
        logging.error(f"Failed to bump the {part} version: {error}")
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
        logging.debug(f"New version retrieved: {version}")
        return version
    except (FileNotFoundError, KeyError, ValueError, toml.TomlDecodeError) as e:
        logging.error(f"Error retrieving the version from {pyproject_path}: {e}")
        sys.exit(1)


def stage_changes(pyproject_path: str = "pyproject.toml") -> None:
    """
    Stages the specified file for commit.

    Args:
        pyproject_path (str): Path to the file to stage.
    """
    try:
        subprocess.run(["git", "add", pyproject_path], check=True)
        logging.debug(f"Staged {pyproject_path} for commit.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to stage {pyproject_path}: {e}")
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
        logging.info("Successfully amended the commit with the new version bump.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to amend the commit: {e}")
        sys.exit(1)


def main() -> None:
    """
    Main function to parse the commit message and perform version bumping and commit message enhancement.
    """

    commit_msg = read_commit_message(args.commit_msg_file)
    updated_commit_msg = add_icon_to_commit_message(commit_msg)
    version_bump_part = determine_version_bump(commit_msg)

    if version_bump_part:
        logging.info(f"Version bump detected: {version_bump_part}")
        bump_version(version_bump_part)
        new_version = get_new_version()

        # Stage the updated pyproject.toml
        stage_changes()

        # Optionally, you can add the new version to the commit message
        # For simplicity, we'll update the commit message with the icon only
        # If needed, modify this section to include the new version in the commit message

        # Amend the commit with the updated commit message
        amend_commit(updated_commit_msg)
    else:
        logging.info("No version bump detected in commit message.")


if __name__ == "__main__":
    args = parse_arguments()
    configure_logger(args.log_level)
    main()
