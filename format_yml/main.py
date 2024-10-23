# scripts/validate_docker_compose.py
import re
import sys
import os

DEBUG = False


def format_yml_file(file_path):
    """
    Function to format yml files

    Args:
        file_path (str):
    """
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()
    new_lines = []

    if not lines or not lines[0].strip().startswith("---"):
        lines.insert(0, "---")
        print(f"[FORMAT] Added '---' at the beginning of {file_path}.")

    for i, line in enumerate(lines):
        original_line = line
        line = re.sub(r"\[\s+", "[", line)
        line = re.sub(r"\s+]", "]", line)
        line = re.sub(r"\(\s+", "(", line)
        line = re.sub(r"\s+\)", ")", line)
        if line != original_line:
            lines[i] = line
            print(f"[FORMAT] Removed extra spaces inside brackets in line {i+1} of {file_path}.")

    for i, line in enumerate(lines, start=1):
        current_indent = len(line) - len(line.lstrip(" "))

        while len(line) > 120:
            split_pos = line.rfind(" ", 0, 120)
            if split_pos != -1:
                split_line1 = line[:split_pos] + " \\"
                split_line2 = " " * current_indent + " " + line[split_pos + 1 :].lstrip()
                new_lines.append(split_line1)
                new_lines.append(split_line2)
                print(f"[FORMAT] Split long line at line {i} in {file_path}.")
                continue
            if not split_pos != -1:
                split_line1 = line[:120] + " \\"
                split_line2 = " " * current_indent + " " + line[120 + 1 :].lstrip()
                new_lines.append(split_line1)
                new_lines.append(split_line2)
                print(f"[FORMAT] Force split long line at line {i} in {file_path}.")
                continue

        new_lines.append(line)

    formatted_content = "\n".join(new_lines) + "\n"

    with open(file_path, "w", newline="\n", encoding="utf-8") as f:
        f.write(formatted_content)

    print(f"[FORMAT] Formatted {file_path} with LF line endings.")
    sys.exit(0)


def main():
    """Main void function to format yml files."""

    if len(sys.argv) < 2:
        print("[ERROR] Incorrect usage. Must specify at least one file.")
        sys.exit(1)

    files_to_validate = sys.argv[1:]
    for file in files_to_validate:
        file_path = os.path.abspath(file)
        if os.path.isfile(file_path):
            format_yml_file(file_path)
        else:
            print(f"[ERROR] File {file_path} does not exist.")
            sys.exit(1)

    print("[OK] All checks passed successfully.")
    sys.exit(0)


if __name__ == "__main__":
    main()
