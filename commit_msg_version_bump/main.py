#!/usr/bin/env python3
"""
commit_msg_version_bump.py

A script to bump the version in pyproject.toml based on commit message keywords.
Handles major, minor, and patch releases.

Usage:
    commit_msg_version_bump.py <commit_msg_file>
"""

import sys
import re
import subprocess
import toml

DEBUG = False


def bump_version(part: str) -> None:
    """
    Bumps the specified part of the version using bump2version and commits the change.

    Args:
        part (str): The part of the version to bump ('major', 'minor', 'patch').

    Raises:
        subprocess.CalledProcessError: If bump2version or git commands fail.
    """
    try:
        subprocess.run(["bump2version", part], check=True)
        print(f"Successfully bumped the {part} version.")
    except subprocess.CalledProcessError:
        print(f"Failed to bump the {part} version.")
        sys.exit(1)

    # Retrieve the new version from pyproject.toml
    new_version = get_new_version()

    if DEBUG:
        print(f"Target version {new_version}")

    # Stage the changed pyproject.toml
    try:
        subprocess.run(["git", "add", "pyproject.toml"], check=True)
    except subprocess.CalledProcessError:
        print("Failed to stage pyproject.toml.")
        sys.exit(1)

    # Commit the change
    try:
        subprocess.run(["git", "commit", "-m", f"Bump {part} version to {new_version}"], check=True)
        print(f"Committed the bumped {part} version to {new_version}.")
    except subprocess.CalledProcessError:
        print(f"Failed to commit the bumped {part} version.")
        sys.exit(1)


def get_new_version() -> str:
    """
    Retrieves the new version from pyproject.toml.

    Returns:
        str: The new version string.

    Raises:
        SystemExit: If the version cannot be retrieved.
    """
    pyproject_path = "pyproject.toml"
    try:
        with open(pyproject_path, "r", encoding="utf-8") as file:
            data = toml.load(file)
        version = data["tool"]["poetry"]["version"]
        return version
    except (FileNotFoundError, KeyError, ValueError, toml.TomlDecodeError):
        print(f"Error: Unable to retrieve the version from {pyproject_path}.")
        sys.exit(1)


def main() -> None:
    """
    Main function to parse the commit message and perform version bumping.
    """
    if DEBUG:
        print(f"Sys: {sys}")

    if len(sys.argv) < 2:
        print("Usage: commit_msg_version_bump.py <commit_msg_file>")
        sys.exit(1)

    commit_msg_file = sys.argv[1]

    try:
        with open(commit_msg_file, "r", encoding="utf-8") as file:
            commit_msg = file.read().strip()
    except FileNotFoundError:
        print(f"Commit message file not found: {commit_msg_file}")
        sys.exit(1)

    if DEBUG:
        print(f"Commit message file: {commit_msg_file}")
        print(f"commit_msg: {commit_msg}")

    # Define patterns for candidate types
    major_pattern = re.compile(r"\bmajor candidate\b", re.IGNORECASE)
    minor_pattern = re.compile(r"\bminor candidate\b", re.IGNORECASE)
    patch_pattern = re.compile(r"\bpatch candidate\b", re.IGNORECASE)

    if major_pattern.search(commit_msg):
        print("Major candidate release detected. Bumping major version...")
        bump_version("major")
    elif minor_pattern.search(commit_msg):
        print("Minor candidate release detected. Bumping minor version...")
        bump_version("minor")
    elif patch_pattern.search(commit_msg):
        print("Patch candidate release detected. Bumping patch version...")
        bump_version("patch")
    else:
        print("No version bump detected in commit message.")


if __name__ == "__main__":
    main()
