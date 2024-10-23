# scripts/validate_docker_compose.py
import re
import sys
import os

DEBUG = False


def format_yaml_file(file_path):
    """
    Format a yaml file

    Args:
        :param file_path:
    """
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.splitlines()

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

    inside_run_block = False
    new_lines = []
    for i, line in enumerate(lines):
        if re.match(r"^run:\s*\|", line):
            inside_run_block = True
            new_lines.append(line)
            continue
        if inside_run_block and re.match(r"^\S", line):
            inside_run_block = False

        if inside_run_block and len(line) > 120:
            split_pos = line.rfind(" ", 0, 120)
            if split_pos != -1:
                split_line1 = line[:split_pos]
                split_line2 = "  " + line[split_pos + 1 :].lstrip()
                new_lines.append(split_line1)
                new_lines.append(split_line2)
                print(f"[FORMAT] Split long line in 'run' block at line {i+1} of {file_path}.")
                continue
            if not split_pos != -1:
                split_line1 = line[:120]
                split_line2 = "  " + line[120:].lstrip()
                new_lines.append(split_line1)
                new_lines.append(split_line2)
                print(f"[FORMAT] Split long line in 'run' block at line {i+1} of {file_path}.")
                continue

        new_lines.append(line)

    formatted_content = "\n".join(lines) + "\n"

    with open(file_path, "w", newline="\n", encoding="utf-8") as f:
        f.write(formatted_content)

    print(f"[FORMAT] Formatted {file_path} with LF line endings.")
    sys.exit(0)


def main():
    """Main void function to format yaml files."""

    if len(sys.argv) < 2:
        print("[ERROR] Incorrect usage. Must specify at least one file.")
        sys.exit(1)

    files_to_validate = sys.argv[1:]
    for file in files_to_validate:
        file_path = os.path.abspath(file)
        if os.path.isfile(file_path):
            format_yaml_file(file_path)
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
