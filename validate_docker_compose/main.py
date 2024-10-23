# scripts/validate_docker_compose.py

import subprocess
import sys
import os

DEBUG = False


def format_docker_compose(file_path):
    """
    Format a docker compose file

    Args:
        :param file_path:
    """
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()

    if not lines or not lines[0].strip().startswith("---"):
        lines.insert(0, "---")
        print(f"[FORMAT] Added '---' at the beginning of {file_path}.")

    formatted_content = "\n".join(lines) + "\n"

    with open(file_path, "w", newline="\n", encoding="utf-8") as f:
        f.write(formatted_content)

    print(f"[FORMAT] Formatted {file_path} with LF line endings.")


def validate_docker_compose(file_path):
    """
    Validate a Docker compose file.

    Args:
        :param file_path:
    """
    try:
        result = subprocess.run(
            ["docker-compose", "-f", file_path, "config"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        print(f"[OK] {file_path} is valid.")
        if DEBUG:
            print(f"[DEBUG] Result response: {result}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Error in file {file_path}:")
        print(e.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("[ERROR] docker-compose not found.")
        sys.exit(1)


def main():
    """Main void function for validating Docker compose files."""

    if len(sys.argv) < 2:
        print("[ERROR] Incorrect usage. Must specify at least one file.")
        sys.exit(1)

    files_to_validate = sys.argv[1:]
    for file in files_to_validate:
        file_path = os.path.abspath(file)
        if os.path.isfile(file_path):
            format_docker_compose(file_path)
            validate_docker_compose(file_path)
        else:
            print(f"[ERROR] File {file_path} does not exist.")
            sys.exit(1)

    print("[OK] All checks passed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    if sys.stdout.encoding.lower() != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except AttributeError:
            import io

            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
