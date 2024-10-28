#!/usr/bin/env python3
"""
Variable Replacement Script

This script processes specified files to replace placeholders with defined variables
or randomly generated strings. It supports various placeholder formats and ensures
that the files adhere to specified formatting rules.

Usage:
    python variable_replacer.py --files <file1> <file2> ... [--log-level LEVEL]

Example:
    python variable_replacer.py --files .env.example config/settings.ini --log-level DEBUG
"""

import argparse
import logging
import os
import re
import random
import string
from logging.handlers import RotatingFileHandler


class ArgumentParser:
    """
    Parses command-line arguments for the script.
    """

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description=(
                "Replace placeholders in specified files with defined variables or randomly generated strings. "
                "Supports placeholders like <VAR_NAME> and <number (Chars)>."
            )
        )
        self.parser.add_argument(
            "--files",
            nargs="+",
            required=True,
            help="List of file paths to process.",
        )
        self.parser.add_argument(
            "--log-level",
            choices=["INFO", "DEBUG"],
            default="INFO",
            help="Set the logging level. Default is INFO.",
        )

    def parse(self) -> argparse.Namespace:
        """
        Parses the command-line arguments.

        Returns:
            argparse.Namespace: Parsed arguments.
        """
        return self.parser.parse_args()


class LoggerConfigurator:
    """
    Configures logging for the script.
    """

    def __init__(self, log_level: str, log_file: str = "variable_replacer.log"):
        """
        Initializes the LoggerConfigurator.

        Args:
            log_level (str): Logging level as a string (e.g., 'INFO', 'DEBUG').
            log_file (str): Path to the log file.
        """
        self.logger = logging.getLogger(__name__)
        self.configure_logger(log_level, log_file)

    def configure_logger(self, log_level: str, log_file: str) -> None:
        """
        Configures the logger with file and console handlers.

        Args:
            log_level (str): Logging level.
            log_file (str): Path to the log file.
        """
        numeric_level = getattr(logging, log_level.upper(), None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {log_level}")

        self.logger.setLevel(numeric_level)

        # File handler with rotation
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(file_formatter)

        # Safe console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(file_formatter)
        console_handler.setLevel(numeric_level)

        # Clear existing handlers and add new ones
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)


class VariableReplacer:
    """
    Handles the replacement of placeholders in files with variables or generated strings.
    """

    PLACEHOLDER_PATTERN = re.compile(r"<(\d+)\s*\((Chars(?:-with-specials)?)\)>")
    VARIABLE_PATTERN = re.compile(r"<([A-Z_]+)>")
    VARIABLE_DEFINITION_PATTERN = re.compile(r'^([A-Z_]+)=["\']?(.*?)["\']?$')

    def __init__(self, logger: logging.Logger):
        """
        Initializes the VariableReplacer.

        Args:
            logger (logging.Logger): Logger instance for logging.
        """
        self.logger = logger
        self.variables = {}

    def generate_random_string(self, length: int, chars_type: str) -> str:
        """
        Generates a random string based on the specified type.

        Args:
            length (int): The length of the generated string.
            chars_type (str): The type of characters to include ('Chars' or 'Chars-with-specials').

        Returns:
            str: The generated random string.
        """
        if chars_type == "Chars":
            characters = string.ascii_letters + string.digits
        elif chars_type == "Chars-with-specials":
            # Exclude problematic characters
            characters = string.ascii_letters + string.digits + "!#%*-_=+;,."
        else:
            characters = string.ascii_letters + string.digits  # Default to 'Chars'

        random_str = "".join(random.choice(characters) for _ in range(length))
        self.logger.debug(f"Generated random string: {random_str}")
        return random_str

    def replace_placeholders(self, line: str) -> str:
        """
        Replaces placeholders in a line based on defined patterns.

        Args:
            line (str): The line containing placeholders.

        Returns:
            str: The line with placeholders replaced.
        """
        # Replace <number (Chars)> and <number (Chars-with-specials)>
        line = self.PLACEHOLDER_PATTERN.sub(
            lambda match: self.generate_random_string(int(match.group(1)), match.group(2)),
            line,
        )

        # Replace <VAR_NAME> with defined variables
        line = self.VARIABLE_PATTERN.sub(self.variable_replacer, line)
        return line

    def variable_replacer(self, match: re.Match) -> str:
        """
        Replacer function for variable placeholders.

        Args:
            match (re.Match): Regex match object.

        Returns:
            str: Replacement string.
        """
        var_name = match.group(1)
        if var_name in self.variables:
            self.logger.debug(f"Replacing variable <{var_name}> with {self.variables[var_name]}")
            return self.variables[var_name]
        else:
            self.logger.warning(
                f"Undefined variable '{var_name}' encountered. Placeholder left as-is."
            )
            return match.group(0)  # Leave the placeholder as-is

    def remove_inline_comments(self, line: str) -> str:
        """
        Removes inline comments from a line. Leaves full-line comments intact.

        Args:
            line (str): The line from which to remove comments.

        Returns:
            str: The line without inline comments.
        """
        stripped_line = line.lstrip()
        if stripped_line.startswith("#"):
            return line  # Leave full-line comments intact

        result = []
        in_single_quote = False
        in_double_quote = False

        for char in line:
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
            elif char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
            elif char == "#" and not in_single_quote and not in_double_quote:
                break  # Ignore the rest of the line after '#'
            result.append(char)

        cleaned_line = "".join(result).rstrip()
        self.logger.debug(f"Removed inline comments: '{line}' -> '{cleaned_line}'")
        return cleaned_line

    def clean_spaces(self, line: str) -> str:
        """
        Cleans unnecessary spaces from a line.

        Args:
            line (str): The line to clean.

        Returns:
            str: The cleaned line.
        """
        original_line = line
        line = line.strip()
        line = re.sub(r"\s+", " ", line)
        self.logger.debug(f"Cleaned spaces: '{original_line}' -> '{line}'")
        return line

    def collect_variables(self, line: str) -> (str, bool):
        """
        Collects variable definitions from a line and updates the variables dictionary.

        Args:
            line (str): The line containing variable definition.

        Returns:
            tuple:
                str: The updated line with placeholders replaced.
                bool: Indicates whether a variable was defined.
        """
        match = self.VARIABLE_DEFINITION_PATTERN.match(line)
        if match:
            var_name = match.group(1)
            var_value = match.group(2)
            self.logger.debug(f"Found variable definition: {var_name}={var_value}")

            # Replace placeholders within the variable value
            var_value_replaced = self.replace_placeholders(var_value)
            self.variables[var_name] = var_value_replaced

            # Reconstruct the line with the replaced value
            quote_match = re.match(rf'^{var_name}=([\'"])(.*)\1$', line)
            if quote_match:
                quote_char = quote_match.group(1)
                line_final = f"{var_name}={quote_char}{var_value_replaced}{quote_char}"
            else:
                line_final = f"{var_name}={var_value_replaced}"
            self.logger.info(f"Defined variable '{var_name}' with value '{var_value_replaced}'")
            return line_final, True

        return line, False

    def process_file(self, file_path: str) -> None:
        """
        Processes a file by replacing placeholders and formatting lines.

        Args:
            file_path (str): Path to the file to process.
        """
        if not os.path.exists(file_path):
            self.logger.error(f"The file {file_path} does not exist.")
            return

        self.logger.info(f"Processing file: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            self.logger.error(f"Failed to read {file_path}: {e}")
            return

        formatted_lines = []

        for i, line in enumerate(lines, start=1):
            original_line = line.rstrip("\n")
            self.logger.debug(f"Original line {i}: {original_line}")

            # Step 1: Remove inline comments (leave full-line comments intact)
            line_no_comments = self.remove_inline_comments(original_line)

            # Step 2: Clean unnecessary spaces
            line_cleaned = self.clean_spaces(line_no_comments)

            # Step 3: Check if the line is a variable definition and collect variables
            line_processed, is_var_def = self.collect_variables(line_cleaned)

            if is_var_def:
                # If it's a variable definition, add the updated line
                if line_processed != original_line.strip():
                    self.logger.info(f"Modified variable definition on line {i} in {file_path}.")
                formatted_lines.append(line_processed)
            else:
                # Step 4: Replace variable placeholders in non-variable lines
                line_replaced = self.replace_placeholders(line_cleaned)

                if line_replaced != line_cleaned:
                    self.logger.debug(f"Modified line {i} in {file_path}.")

                # Step 5: Add the formatted line if it's not empty
                if line_replaced:
                    formatted_lines.append(line_replaced)
                else:
                    # If the line is empty after cleaning (e.g., was a comment-only line), do not add it
                    self.logger.debug(f"Removed empty or comment-only line {i} in {file_path}.")

        # Combine all formatted lines
        formatted_content = "\n".join(formatted_lines) + "\n"

        try:
            with open(file_path, "w", newline="\n", encoding="utf-8") as f:
                f.write(formatted_content)
            self.logger.info(f"Formatted {file_path} successfully.")
        except Exception as e:
            self.logger.error(f"Failed to write to {file_path}: {e}")


def main():
    """
    Main function to handle command-line arguments and initiate file processing.
    """
    # Parse arguments
    arg_parser = ArgumentParser()
    args = arg_parser.parse()

    # Configure logger
    logger_config = LoggerConfigurator(log_level=args.log_level)
    logger = logger_config.logger

    # Initialize VariableReplacer
    replacer = VariableReplacer(logger)

    # Process each specified file
    for file_path in args.files:
        replacer.process_file(file_path)


if __name__ == "__main__":
    main()
