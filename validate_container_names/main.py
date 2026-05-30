# scripts/validate_container_names/main.py

import re
import sys
import os

# Container template naming convention: Container{SUITE}{APP}{ENV}.yml
# Rules:
#   - Must start with literal "Container"
#   - Followed by SUITE+APP in uppercase alphanumeric (min 2 chars)
#   - Must end with exactly one environment suffix: PROD | TEST | DEV
#   - Extension must be .yml
VALID_ENVS = ("PROD", "TEST", "DEV")
CONTAINER_NAME_REGEX = re.compile(r"^Container[A-Z0-9]{2,}(?:PROD|TEST|DEV)\.yml$")


def validate_filename(file_path):
    """
    Validate that a CloudFormation template filename follows the convention:
    Container{SUITE}{APP}{ENV}.yml

    Args:
        :param file_path: Path to the CloudFormation template file
    :returns: True if valid, False otherwise
    """
    basename = os.path.basename(file_path)

    if not CONTAINER_NAME_REGEX.match(basename):
        env_hint = " | ".join(VALID_ENVS)
        print(
            f"[ERROR] '{basename}' does not follow the naming convention.\n"
            f"        Expected: Container{{SUITE}}{{APP}}{{{env_hint}}}.yml\n"
            f"        Rules:\n"
            f"          - Must start with 'Container'\n"
            f"          - SUITE and APP must be uppercase alphanumeric (no hyphens, underscores or spaces)\n"
            f"          - Must end with one of: {env_hint}\n"
            f"          - Extension must be .yml\n"
            f"        Example: ContainerGESTIONATENCIONBACKPROD.yml"
        )
        return False

    # Extract the env suffix for informational output
    name_no_ext = basename[: -len(".yml")]
    env = next(e for e in VALID_ENVS if name_no_ext.endswith(e))
    suite_app = name_no_ext[len("Container") : -len(env)]
    print(f"[OK] '{basename}' — suite+app: '{suite_app}', env: '{env}'")
    return True


def main():
    """Main function for validating Container CloudFormation template filenames."""

    if len(sys.argv) < 2:
        print("[ERROR] Incorrect usage. Must specify at least one file.")
        sys.exit(1)

    files = sys.argv[1:]
    errors = []

    for file in files:
        if not validate_filename(file):
            errors.append(os.path.basename(file))

    if errors:
        print(f"\n[FAIL] {len(errors)} file(s) with invalid names: {', '.join(errors)}")
        sys.exit(1)

    print(f"[OK] All {len(files)} file(s) passed naming validation.")
    sys.exit(0)


if __name__ == "__main__":
    if sys.stdout.encoding.lower() != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except AttributeError:
            import io

            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    main()
