# tests/test_init_security_config.py

import logging
import string
import sys

import pytest

import init_security_config.main as isc
from init_security_config.main import ArgumentParser, LoggerConfigurator, VariableReplacer

ALNUM = string.ascii_letters + string.digits
SPECIALS = ALNUM + "!#%*-_=+;,."


@pytest.fixture
def replacer():
    """VariableReplacer wired to a quiet test logger."""
    return VariableReplacer(logging.getLogger("test_init_security_config"))


def test_generate_random_string_chars(replacer):
    """'Chars' produces alphanumeric strings of the requested length."""
    value = replacer.generate_random_string(16, "Chars")
    assert len(value) == 16
    assert all(char in ALNUM for char in value)


def test_generate_random_string_with_specials(replacer):
    """'Chars-with-specials' draws from the extended character set."""
    value = replacer.generate_random_string(24, "Chars-with-specials")
    assert len(value) == 24
    assert all(char in SPECIALS for char in value)


def test_generate_random_string_unknown_type_defaults_to_chars(replacer):
    """An unknown chars type falls back to alphanumeric."""
    value = replacer.generate_random_string(8, "Unknown")
    assert len(value) == 8
    assert all(char in ALNUM for char in value)


def test_replace_placeholders_random(replacer):
    """<N (Chars)> placeholders are replaced by generated strings."""
    line = replacer.replace_placeholders("TOKEN=<8 (Chars)>")
    assert "<" not in line
    assert len(line) == len("TOKEN=") + 8


def test_replace_placeholders_defined_variable(replacer):
    """<VAR> placeholders resolve against collected variables."""
    replacer.variables["FOO"] = "bar"
    assert replacer.replace_placeholders("value: <FOO>") == "value: bar"


def test_replace_placeholders_undefined_variable_left_as_is(replacer):
    """Undefined <VAR> placeholders stay untouched."""
    assert replacer.replace_placeholders("value: <MISSING>") == "value: <MISSING>"


def test_remove_inline_comments_keeps_full_line_comments(replacer):
    """Full-line comments are preserved."""
    assert replacer.remove_inline_comments("# full comment") == "# full comment"


def test_remove_inline_comments_strips_trailing_comment(replacer):
    """Inline comments after values are removed."""
    assert replacer.remove_inline_comments("KEY=value # note") == "KEY=value"


def test_remove_inline_comments_respects_quotes(replacer):
    """Hashes inside quotes are not treated as comments."""
    assert replacer.remove_inline_comments("KEY='a # b'") == "KEY='a # b'"
    assert replacer.remove_inline_comments('KEY="a # b" # real') == 'KEY="a # b"'


def test_clean_spaces(replacer):
    """Surrounding and repeated whitespace is collapsed."""
    assert replacer.clean_spaces("  a    b  ") == "a b"


def test_collect_variables_quoted_definition(replacer):
    """A quoted variable definition is collected and reconstructed."""
    line, is_def = replacer.collect_variables('TOKEN="abc"')
    assert is_def is True
    assert line == 'TOKEN="abc"'
    assert replacer.variables["TOKEN"] == "abc"


def test_collect_variables_unquoted_definition(replacer):
    """An unquoted variable definition is collected."""
    line, is_def = replacer.collect_variables("TOKEN=abc")
    assert is_def is True
    assert line == "TOKEN=abc"
    assert replacer.variables["TOKEN"] == "abc"


def test_collect_variables_resolves_placeholders_in_value(replacer):
    """Placeholders inside the defined value are resolved before storing."""
    line, is_def = replacer.collect_variables('SECRET="<6 (Chars)>"')
    assert is_def is True
    assert len(replacer.variables["SECRET"]) == 6
    assert line == f'SECRET="{replacer.variables["SECRET"]}"'


def test_collect_variables_ignores_non_definitions(replacer):
    """Lines that are not variable definitions pass through."""
    line, is_def = replacer.collect_variables("just some text")
    assert is_def is False
    assert line == "just some text"


def test_process_file_end_to_end(replacer, tmp_path):
    """A template file is fully resolved: comments, placeholders and blank lines."""
    env_file = tmp_path / ".env.example"
    env_file.write_text(
        "# Database settings\n"
        'TOKEN="<8 (Chars)>"\n'
        "URL=https://example.com  # endpoint\n"
        "REF=<TOKEN>\n"
        "\n",
        encoding="utf-8",
    )
    replacer.process_file(str(env_file))
    lines = env_file.read_text(encoding="utf-8").splitlines()

    assert lines[0] == "# Database settings"
    token_value = lines[1].split("=", 1)[1].strip('"')
    assert len(token_value) == 8
    assert lines[2] == "URL=https://example.com"
    assert lines[3] == f"REF={token_value}"
    assert len(lines) == 4  # the blank line was dropped


def test_process_file_missing_file_logs_error(replacer, tmp_path, caplog):
    """A nonexistent file logs an error and does not raise."""
    with caplog.at_level(logging.ERROR, logger="test_init_security_config"):
        replacer.process_file(str(tmp_path / "missing.env"))
    assert "does not exist" in caplog.text


def test_process_file_read_error_logs_error(replacer, tmp_path, caplog):
    """An unreadable file logs a read failure and does not raise."""
    env_file = tmp_path / ".env.example"
    env_file.write_text("KEY=value\n", encoding="utf-8")
    env_file.chmod(0o000)
    try:
        with caplog.at_level(logging.ERROR, logger="test_init_security_config"):
            replacer.process_file(str(env_file))
    finally:
        env_file.chmod(0o644)
    assert "Failed to read" in caplog.text


def test_logger_configurator_invalid_level_raises(tmp_path, monkeypatch):
    """An unknown log level raises ValueError."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="Invalid log level"):
        LoggerConfigurator(log_level="NOISY")


def test_logger_configurator_sets_handlers(tmp_path, monkeypatch):
    """A valid level configures file and console handlers."""
    monkeypatch.chdir(tmp_path)
    configurator = LoggerConfigurator(log_level="DEBUG")
    assert len(configurator.logger.handlers) == 2


def test_argument_parser_parses_files(monkeypatch):
    """--files collects every path passed."""
    monkeypatch.setattr(sys, "argv", ["init_security_config", "--files", "a.env", "b.ini"])
    args = ArgumentParser().parse()
    assert args.files == ["a.env", "b.ini"]
    assert args.log_level == "INFO"


def test_argument_parser_requires_files(monkeypatch):
    """Missing --files makes argparse exit with code 2."""
    monkeypatch.setattr(sys, "argv", ["init_security_config"])
    with pytest.raises(SystemExit) as exc_info:
        ArgumentParser().parse()
    assert exc_info.value.code == 2


def test_main_processes_files(tmp_path, monkeypatch):
    """main() resolves placeholders of every file passed via --files."""
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env.example"
    env_file.write_text('SECRET="<10 (Chars)>"\n', encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["init_security_config", "--files", str(env_file)])
    isc.main()
    content = env_file.read_text(encoding="utf-8")
    assert "<10 (Chars)>" not in content
    secret_value = content.strip().split("=", 1)[1].strip('"')
    assert len(secret_value) == 10
