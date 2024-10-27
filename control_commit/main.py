#!/usr/bin/env python3
"""
commit_msg_icon_adder.py

A script to validate commit messages and add appropriate icons based on commit types.
Ensures that commit messages follow a specific structure and naming conventions.
Adds icons to commit messages that do not contain square brackets [].

Usage:
    commit_msg_icon_adder.py [--log-level {INFO,DEBUG}] <commit_msg_file>
"""

import argparse
import logging
import re
import sys
from logging.handlers import RotatingFileHandler

# Mapping of commit types to icons
TYPE_MAPPING = {
    "feat": "✨",
    "fix": "🐛",
    "docs": "📝",
    "style": "💄",
    "refactor": "♻️",
    "perf": "⚡️",
    "test": "✅",
    "chore": "🔧",
}

# Regular expressions for detecting commit types and validating commit message structure
COMMIT_TYPE_REGEX = re.compile(r"^(?P<type>feat|fix|docs|style|refactor|perf|test|chore)")
COMMIT_MESSAGE_REGEX = re.compile(
    r"^(?P<type>feat|fix|docs|style|refactor|perf|test|chore)"
    r"(?:\((?P<scope>[a-z0-9\-]+)\))?:\s+"
    r"(?P<description>[a-z].+)$"
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
            "Validate commit messages and add icons based on commit types. "
            "Ensures commit messages follow the format: type(scope): description."
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
        "commit_msg_icon_adder.log", maxBytes=5 * 1024 * 1024, backupCount=5
    )
    console_handler = logging.StreamHandler()

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def read_commit_message(file_path: str) -> str:
    """
    Reads the commit message from the given file.

    Args:
        file_path (str): Path to the commit message file.

    Returns:
        str: The commit message.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            commit_msg = file.read().strip()
            logger.debug(f"Original commit message: {commit_msg}")
            return commit_msg
    except FileNotFoundError:
        logger.error(f"Commit message file not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading commit message file: {e}")
        sys.exit(1)


def validate_commit_message(commit_msg: str) -> bool:
    """
    Validates the commit message against the required structure and lowercase naming.

    Args:
        commit_msg (str): The commit message to validate.

    Returns:
        bool: True if valid, False otherwise.
    """
    match = COMMIT_MESSAGE_REGEX.match(commit_msg)
    if match:
        logger.debug("Commit message structure is valid.")
        return True
    else:
        logger.error("Invalid commit message structure. Ensure it follows the format:")
        logger.error("type(scope): description")
        logger.error(" - type: feat, fix, docs, style, refactor, perf, test, chore (lowercase)")
        logger.error(" - scope: optional, lowercase, alphanumeric and hyphens")
        logger.error(" - description: starts with a lowercase letter")
        return False


def add_icon_to_commit_message(commit_type: str, existing_commit_msg: str) -> str:
    """
    Adds an icon to the commit message based on its type if it doesn't already have one.

    Args:
        commit_type (str): The type of the commit (e.g., 'chore', 'fix').
        existing_commit_msg (str): The original commit message.

    Returns:
        str: The commit message with the icon prepended.
    """
    icon = TYPE_MAPPING.get(commit_type.lower(), "")
    if not existing_commit_msg.startswith(icon):
        new_commit_msg = f"{icon} {existing_commit_msg}"
        logger.debug(f"Updated commit message with icon: {new_commit_msg}")
        return new_commit_msg
    logger.debug("Icon already present in commit message.")
    return existing_commit_msg


def write_commit_message(file_path: str, commit_msg: str) -> None:
    """
    Writes the updated commit message back to the commit message file.

    Args:
        file_path (str): Path to the commit message file.
        commit_msg (str): The updated commit message.
    """
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(commit_msg + "\n")
        logger.debug(f"Commit message written to file: {file_path}")
    except Exception as e:
        logger.error(f"Error writing to commit message file: {e}")
        sys.exit(1)


def main() -> None:
    """
    Main function to validate commit messages and add icons if necessary.
    Exits with code 1 if validation fails.
    """
    args = parse_arguments()
    configure_logger(args.log_level)

    commit_msg_file = ".git/COMMIT_EDITMSG"
    commit_msg = read_commit_message(commit_msg_file)

    # Validate the commit message structure and naming
    if not validate_commit_message(commit_msg):
        logger.error("Commit message validation failed. Aborting commit.")
        sys.exit(1)

    # Check if the commit message contains square brackets
    if not has_square_brackets(commit_msg):
        logger.debug("Commit message does not contain square brackets. Proceeding to add icon.")

        # Determine the type of commit to get the appropriate icon
        type_match = COMMIT_TYPE_REGEX.match(commit_msg)
        if type_match:
            commit_type = type_match.group("type")
            logger.debug(f"Detected commit type: {commit_type}")
        else:
            commit_type = "chore"  # Default to 'chore' if no type is found
            logger.debug("No commit type detected. Defaulting to 'chore'.")
            exit(1)

        # Add the icon to the existing commit message
        updated_commit_msg = add_icon_to_commit_message(commit_type, commit_msg)

        # Write the updated commit message back to the file
        write_commit_message(commit_msg_file, updated_commit_msg)

        # Inform the user and abort the commit to allow them to review the amended message
        logger.info(
            "Commit message has been updated with an icon. Please review the commit message."
        )
        sys.exit(1)
    else:
        logger.debug("Commit message contains square brackets. No icon added.")


def has_square_brackets(commit_msg: str) -> bool:
    """
    Checks if the commit message contains square brackets.

    Args:
        commit_msg (str): The commit message.

    Returns:
        bool: True if square brackets are present, False otherwise.
    """
    return bool(re.search(r"\[.*?]", commit_msg))


if __name__ == "__main__":
    main()
