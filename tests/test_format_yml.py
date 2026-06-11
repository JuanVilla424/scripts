# tests/test_format_yml.py

import sys

import pytest

from format_yml.main import format_yml_file, main


def _write(tmp_path, name, content):
    file_path = tmp_path / name
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def test_adds_document_start_marker(tmp_path, capsys):
    """A yml file without '---' gets the marker prepended."""
    file_path = _write(tmp_path, "config.yml", "key: value\n")
    format_yml_file(file_path)
    content = (tmp_path / "config.yml").read_text(encoding="utf-8")
    assert content.startswith("---\n")
    assert "Added '---' at the beginning" in capsys.readouterr().out


def test_keeps_existing_marker(tmp_path, capsys):
    """A yml file that already starts with '---' is not modified."""
    file_path = _write(tmp_path, "config.yml", "---\nkey: value\n")
    format_yml_file(file_path)
    content = (tmp_path / "config.yml").read_text(encoding="utf-8")
    assert content == "---\nkey: value\n"
    assert "Added '---'" not in capsys.readouterr().out


def test_removes_extra_spaces_inside_brackets(tmp_path, capsys):
    """Spaces right after '[' / '(' and before ']' / ')' are removed."""
    file_path = _write(tmp_path, "config.yml", "---\nlist: [ a, b ]\ncmd: ( x )\n")
    format_yml_file(file_path)
    content = (tmp_path / "config.yml").read_text(encoding="utf-8")
    assert "list: [a, b]" in content
    assert "cmd: (x)" in content
    assert "Removed extra spaces inside brackets" in capsys.readouterr().out


def test_splits_long_line_and_terminates(tmp_path, capsys):
    """Lines longer than 120 chars are split into ' \\' continuations and the loop ends."""
    long_line = "key: " + ("abc " * 40).strip()  # 164 chars with plenty of spaces
    file_path = _write(tmp_path, "config.yml", f"---\n{long_line}\n")
    format_yml_file(file_path)
    content = (tmp_path / "config.yml").read_text(encoding="utf-8")
    lines = content.splitlines()
    assert len(lines) >= 3  # marker + at least two split parts
    assert lines[1].endswith(" \\")
    assert all(len(line) <= 122 for line in lines)
    assert content.count("abc") == 40  # no content lost in the split
    assert "Split long line" in capsys.readouterr().out


def test_force_splits_long_line_without_spaces(tmp_path, capsys):
    """A long line without spaces is hard-split at column 120."""
    long_line = "key" + "a" * 130
    file_path = _write(tmp_path, "config.yml", f"---\n{long_line}\n")
    format_yml_file(file_path)
    content = (tmp_path / "config.yml").read_text(encoding="utf-8")
    lines = content.splitlines()
    assert lines[1] == long_line[:120] + " \\"
    assert lines[2].lstrip() == long_line[120:]
    assert "Force split long line" in capsys.readouterr().out


def test_line_at_exactly_120_chars_is_untouched(tmp_path):
    """A line of exactly 120 chars is not split."""
    exact_line = "k: " + "a" * 117
    assert len(exact_line) == 120
    file_path = _write(tmp_path, "config.yml", f"---\n{exact_line}\n")
    format_yml_file(file_path)
    content = (tmp_path / "config.yml").read_text(encoding="utf-8")
    assert content == f"---\n{exact_line}\n"


def test_main_processes_all_files(monkeypatch, tmp_path, capsys):
    """main() formats every file passed, not only the first one."""
    file_a = _write(tmp_path, "a.yml", "key: a\n")
    file_b = _write(tmp_path, "b.yml", "key: b\n")
    monkeypatch.setattr(sys, "argv", ["format_yml", file_a, file_b])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    assert (tmp_path / "a.yml").read_text(encoding="utf-8").startswith("---\n")
    assert (tmp_path / "b.yml").read_text(encoding="utf-8").startswith("---\n")
    assert "All checks passed successfully." in capsys.readouterr().out


def test_main_without_arguments_exits_1(monkeypatch, capsys):
    """main() exits with code 1 when no files are passed."""
    monkeypatch.setattr(sys, "argv", ["format_yml"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    assert "Incorrect usage" in capsys.readouterr().out


def test_main_missing_file_exits_1(monkeypatch, tmp_path, capsys):
    """main() exits with code 1 when a file does not exist."""
    missing = str(tmp_path / "nope.yml")
    monkeypatch.setattr(sys, "argv", ["format_yml", missing])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    assert "does not exist" in capsys.readouterr().out
