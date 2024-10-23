#!/usr/bin/env python3
"""
bump_year.py

A script to bump the year part of the version in pyproject.toml.
Resets major and minor versions to 0 when the year is incremented.

Usage:
    bump_year.py
"""

import datetime
import toml
import sys


def bump_year() -> None:
    """
    Bumps the year in pyproject.toml and resets major and minor versions to 0.
    """
    current_year = datetime.datetime.now().year
    pyproject_path = "pyproject.toml"

    try:
        with open(pyproject_path, "r", encoding="utf-8") as file:
            data = toml.load(file)
    except FileNotFoundError:
        print(f"Error: {pyproject_path} not found.")
        sys.exit(1)
    except toml.TomlDecodeError:
        print(f"Error: Failed to parse {pyproject_path}.")
        sys.exit(1)

    try:
        version = data["tool"]["poetry"]["version"]
        year, major, minor = version.split(".")
    except (KeyError, ValueError):
        print("Error: Version format is incorrect in pyproject.toml.")
        sys.exit(1)

    if int(year) < current_year:
        print(f"Updating year from {year} to {current_year}")
        year = str(current_year)
        major = "0"
        minor = "0"
        new_version = f"{year}.{major}.{minor}"
        data["tool"]["poetry"]["version"] = new_version
        try:
            with open(pyproject_path, "w", encoding="utf-8") as file:
                toml.dump(data, file)
            print(f"Year bumped to {new_version}")
        except Exception as e:
            print(f"Error writing to {pyproject_path}: {e}")
            sys.exit(1)
    else:
        print("Year is up-to-date. No need to bump.")


def main() -> None:
    """
    Main function to execute the year bumping process.
    """
    bump_year()


if __name__ == "__main__":
    main()
