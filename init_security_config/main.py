import re
import sys
import random
import string
import os
import shutil


def generate_random_string(length, chars_type):
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
        # Exclude single quotes, double quotes, and backslashes, $, :, &, @, [], (), /, |
        characters = string.ascii_letters + string.digits + "!#%*-_=+;,."
    else:
        characters = string.ascii_letters + string.digits  # Default to 'Chars' if unknown

    return "".join(random.choice(characters) for _ in range(length))


def replace_placeholders(line, variables):
    """
    Replaces placeholders in a line based on defined patterns.

    Args:
        line (str): The line containing placeholders.
        variables (dict): Dictionary of previously defined variables.

    Returns:
        str: The line with placeholders replaced.
    """
    # Pattern for <number (Chars)> and <number (Chars-with-specials)>
    placeholder_pattern = re.compile(r"<(\d+)\s*\((Chars(?:-with-specials)?)\)>")

    def placeholder_replacer(match):
        length = int(match.group(1))
        chars_type = match.group(2)
        return generate_random_string(length, chars_type)

    # Replace all <number (Chars)> and <number (Chars-with-specials)> placeholders
    line = placeholder_pattern.sub(placeholder_replacer, line)

    # Pattern for variables like <VAR_NAME>
    var_pattern = re.compile(r"<([A-Z_]+)>")

    def var_replacer(match):
        var_name = match.group(1)
        if var_name in variables:
            return variables[var_name]
        print(f"[WARNING] Undefined variable '{var_name}' encountered. Placeholder left as-is.")
        return match.group(0)  # Leave the placeholder as-is if not defined

    # Replace <VAR_NAME> placeholders with their corresponding values
    line = var_pattern.sub(var_replacer, line)
    return line


def remove_comments(line):
    """
    Removes inline comments from a line. Leaves full-line comments intact.

    Args:
        line (str): The line from which to remove comments.

    Returns:
        str: The line without inline comments. Full-line comments are left intact.
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

    return "".join(result).rstrip()


def clean_spaces(line):
    """
    Cleans unnecessary spaces from a line.

    Args:
        line (str): The line to clean.

    Returns:
        str: The cleaned line.
    """
    # Remove leading and trailing spaces
    line = line.strip()
    # Replace multiple spaces with a single space
    line = re.sub(r"\s+", " ", line)
    return line


def collect_variables(line, variables):
    """
    Collects variable definitions from a line and updates the variables dictionary.

    Args:
        line (str): The line containing variable definition.
        variables (dict): Dictionary to store variable names and their values.

    Returns:
        tuple:
            str: The updated line with placeholders replaced.
            bool: Indicates whether a variable was defined.
    """
    # Pattern to capture lines like VAR_NAME=valor
    var_def_pattern = re.compile(r'^([A-Z_]+)=["\']?(.*?)["\']?$')
    match = var_def_pattern.match(line)
    if match:
        var_name = match.group(1)
        var_value = match.group(2)
        # Replace placeholders within the variable value
        var_value_replaced = replace_placeholders(var_value, variables)
        variables[var_name] = var_value_replaced
        # Reconstruct the line with the replaced value
        # Preserve the original quotes if they were present
        if line.strip().startswith(var_name + "='") or line.strip().startswith(var_name + '="'):
            quote_char = line.strip()[len(var_name) + 1]
            line_final = f"{var_name}={quote_char}{var_value_replaced}{quote_char}"
        else:
            line_final = f"{var_name}={var_value_replaced}"
        return line_final, True  # Indicate that a variable was defined
    return line, False  # No variable defined


def format_env_file(file_path, variables):
    """
    Formats a .env.example file by replacing placeholders, replacing variables,
    removing inline comments, and cleaning spaces.

    Args:
        file_path (str): Path to the .env.example file.
        variables (dict): Dictionary of previously defined variables.

    Returns:
        None
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] The file {file_path} does not exist.")
        sys.exit(1)

    formatted_lines = []

    for i, line in enumerate(lines, start=1):
        original_line = line.rstrip("\n")

        # Step 1: Remove inline comments (leave full-line comments intact)
        line_no_comments = remove_comments(original_line)

        # Step 2: Clean unnecessary spaces
        line_cleaned = clean_spaces(line_no_comments)

        # Step 3: Check if the line is a variable definition and collect variables
        line_processed, is_var_def = collect_variables(line_cleaned, variables)

        if is_var_def:
            # If it's a variable definition, add the updated line
            if line_processed != original_line.strip():
                print(f"[FORMAT] Modified variable definition on line {i} in {file_path}.")
            formatted_lines.append(line_processed)
        else:
            # Step 4: Replace variable placeholders in non-variable lines
            line_replaced = replace_placeholders(line_cleaned, variables)

            if line_replaced != line_cleaned:
                print(f"[FORMAT] Modified line {i} in {file_path}.")

            # Step 5: Add the formatted line if it's not empty
            if line_replaced:
                formatted_lines.append(line_replaced)
            else:
                # If the line is empty after cleaning (e.g., was a comment-only line), do not add it
                print(f"[FORMAT] Removed empty or comment-only line {i} in {file_path}.")

    # Combine all formatted lines
    formatted_content = "\n".join(formatted_lines) + "\n"

    # Write the formatted content back to the file
    with open(file_path, "w", newline="\n", encoding="utf-8") as f:
        f.write(formatted_content)

    print(f"[FORMAT] Formatted {file_path} successfully.")


def format_js_file(file_path, variables):
    """
    Formats a JavaScript (.js) file by replacing placeholders, replacing variables,
    removing inline comments, cleaning spaces, and ensuring proper indentation.

    Args:
        file_path (str): Path to the JavaScript file to format.
        variables (dict): Dictionary of previously defined variables.

    Returns:
        None
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            js_lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] The file {file_path} does not exist.")
        return

    formatted_lines = []
    indent_level = 0
    indent_size = 4  # Number of spaces for each indent level

    for i, line in enumerate(js_lines, start=1):
        original_line = line.rstrip("\n")

        # Step 1: Remove inline comments (leave full-line comments intact)
        line_no_comments = remove_comments(original_line)

        # Step 2: Clean unnecessary spaces
        line_cleaned = clean_spaces(line_no_comments)

        # Step 3: Replace placeholders
        line_replaced = replace_placeholders(line_cleaned, variables)

        if line_replaced != line_cleaned:
            print(f"[FORMAT] Modified line {i} in {file_path}.")

        # Step 4: Determine if the line affects indentation
        # Decrease indent level if the line starts with a closing brace
        if line_replaced.startswith("}") and not line_replaced.endswith("},"):
            indent_level = max(indent_level - 1, 0)
        if line_replaced.startswith("}") and not line_replaced.endswith("],"):
            indent_level = max(indent_level - 1, 0)

        # Apply indentation
        indented_line = " " * (indent_size * indent_level) + line_replaced
        formatted_lines.append(indented_line)

        # Step 5: Adjust indent level based on braces
        # Avoid counting braces within strings
        in_single_quote = False
        in_double_quote = False
        escape_char = False
        for char in line_replaced:
            if escape_char:
                escape_char = False
                continue
            if char == "\\":
                escape_char = True
                continue
            if char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
                continue
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                continue
            if in_single_quote or in_double_quote:
                continue
            if char == "{":
                indent_level += 1
            elif char == "}":
                indent_level = max(indent_level - 1, 0)
            if char == "[":
                indent_level += 1
            elif char == "]":
                indent_level = max(indent_level - 1, 0)

    # Combine all formatted lines
    formatted_content = "\n".join(formatted_lines) + "\n"

    # Write the formatted content back to the file
    with open(file_path, "w", newline="\n", encoding="utf-8") as f:
        f.write(formatted_content)

    print(f"[FORMAT] Formatted {file_path} successfully.")


def ensure_js_file(default_js_path, template_js_path):
    """
    Ensures that the JavaScript file exists. If not, creates it from the template.

    Args:
        default_js_path (str): The default path to the JavaScript file.
        template_js_path (str): The path to the template JavaScript file.

    Returns:
        None
    """
    if not os.path.exists(default_js_path):
        if os.path.exists(template_js_path):
            # Create directories if they do not exist
            os.makedirs(os.path.dirname(default_js_path), exist_ok=True)
            shutil.copyfile(template_js_path, default_js_path)
            print(f"[INFO] Created JavaScript file from template: {default_js_path}")
        else:
            print(f"[ERROR] Template JavaScript file does not exist: {template_js_path}")
            sys.exit(1)
    else:
        print(f"[INFO] JavaScript file already exists: {default_js_path}")


def format_file(file_path, variables):
    """
    Determines the file type and applies appropriate formatting.

    Args:
        file_path (str): Path to the file to format.
        variables (dict): Dictionary of previously defined variables.

    Returns:
        None
    """
    if file_path.endswith(".env") or file_path.endswith(".env.example") or ".env." in file_path:
        format_env_file(file_path, variables)
    elif file_path.endswith(".js"):
        format_js_file(file_path, variables)
    else:
        print(f"[INFO] Skipping unsupported file type: {file_path}")


def main():
    """
    Main function to handle command-line arguments and initiate file formatting.

    Usage:
        python init_security_config.py <path_to_env.example> [<path_to_js_file>]
    """
    if len(sys.argv) < 2:
        print("Usage: python init_security_config.py <path_to_env.example> [<path_to_js_file>]")
        sys.exit(1)

    env_file_path = sys.argv[1]
    if len(sys.argv) >= 3:
        js_file_path = sys.argv[2]
    else:
        # Set default JavaScript file path
        js_file_path = os.path.join("yoguis_tickets_database", "initdb.d", "mongo-init.js")
        template_js_path = os.path.join(
            "yoguis_tickets_database", "initdb.d", "mongo-init.example.js"
        )
        ensure_js_file(js_file_path, template_js_path)

    variables = {}

    # Process the .env.example file
    print(f"\nProcessing file: {env_file_path}")
    format_file(env_file_path, variables)

    # Process the JavaScript file
    if js_file_path:
        print(f"\nProcessing file: {js_file_path}")
        format_file(js_file_path, variables)


if __name__ == "__main__":
    main()
