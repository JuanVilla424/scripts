# tests/test_format_yaml.py

import sys

import pytest

from format_yaml.main import format_yaml_file, main


def _write(tmp_path, name, content):
    file_path = tmp_path / name
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def test_adds_document_start_marker(tmp_path, capsys):
    """A yaml file without '---' gets the marker prepended."""
    file_path = _write(tmp_path, "workflow.yaml", "key: value\n")
    format_yaml_file(file_path)
    content = (tmp_path / "workflow.yaml").read_text(encoding="utf-8")
    assert content.startswith("---\n")
    assert "Added '---' at the beginning" in capsys.readouterr().out


def test_keeps_existing_marker(tmp_path, capsys):
    """A yaml file that already starts with '---' is not modified."""
    file_path = _write(tmp_path, "workflow.yaml", "---\nkey: value\n")
    format_yaml_file(file_path)
    content = (tmp_path / "workflow.yaml").read_text(encoding="utf-8")
    assert content == "---\nkey: value\n"
    assert "Added '---'" not in capsys.readouterr().out


def test_removes_extra_spaces_inside_brackets(tmp_path, capsys):
    """Spaces right after '[' / '(' and before ']' / ')' are removed."""
    file_path = _write(tmp_path, "workflow.yaml", "---\nlist: [ a, b ]\ncmd: ( x )\n")
    format_yaml_file(file_path)
    content = (tmp_path / "workflow.yaml").read_text(encoding="utf-8")
    assert "list: [a, b]" in content
    assert "cmd: (x)" in content
    assert "Removed extra spaces inside brackets" in capsys.readouterr().out


def test_splits_long_line_inside_run_block(tmp_path, capsys):
    """Long lines inside a 'run: |' block are split and the split reaches the output file."""
    long_line = "    " + ("word " * 30).strip()  # 153 chars, indented
    content = f"---\nrun: |\n{long_line}\ndone: true\n"
    file_path = _write(tmp_path, "workflow.yaml", content)
    format_yaml_file(file_path)
    result = (tmp_path / "workflow.yaml").read_text(encoding="utf-8")
    lines = result.splitlines()
    assert len(lines) == 5  # ---, run: |, two split parts, done: true
    assert lines[2].startswith("    word")
    assert lines[3].startswith("  word")
    assert result.count("word") == 30  # no content lost in the split
    assert "Split long line in 'run' block" in capsys.readouterr().out


def test_force_splits_run_block_line_without_spaces(tmp_path, capsys):
    """A run-block line with no spaces is hard-split at column 120."""
    long_line = "\t" + "a" * 130  # tab keeps it inside the run block
    content = f"---\nrun: |\n{long_line}\n"
    file_path = _write(tmp_path, "workflow.yaml", content)
    format_yaml_file(file_path)
    result = (tmp_path / "workflow.yaml").read_text(encoding="utf-8")
    lines = result.splitlines()
    assert lines[2] == long_line[:120]
    assert lines[3] == "  " + long_line[120:]
    assert "Split long line in 'run' block" in capsys.readouterr().out


def test_long_line_outside_run_block_is_untouched(tmp_path):
    """Lines longer than 120 chars outside run blocks are not split."""
    long_line = "key: " + "a" * 130
    file_path = _write(tmp_path, "workflow.yaml", f"---\n{long_line}\n")
    format_yaml_file(file_path)
    content = (tmp_path / "workflow.yaml").read_text(encoding="utf-8")
    assert content == f"---\n{long_line}\n"


def test_non_indented_line_exits_run_block(tmp_path):
    """A non-indented line closes the run block, so later long lines are untouched."""
    long_line = "    " + ("word " * 30).strip()
    content = f"---\nrun: |\n    short\ndone: true\n{long_line}\n"
    file_path = _write(tmp_path, "workflow.yaml", content)
    format_yaml_file(file_path)
    result = (tmp_path / "workflow.yaml").read_text(encoding="utf-8")
    assert long_line in result.splitlines()  # still one single line


def test_main_processes_all_files(monkeypatch, tmp_path, capsys):
    """main() formats every file passed, not only the first one."""
    file_a = _write(tmp_path, "a.yaml", "key: a\n")
    file_b = _write(tmp_path, "b.yaml", "key: b\n")
    monkeypatch.setattr(sys, "argv", ["format_yaml", file_a, file_b])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    assert (tmp_path / "a.yaml").read_text(encoding="utf-8").startswith("---\n")
    assert (tmp_path / "b.yaml").read_text(encoding="utf-8").startswith("---\n")
    assert "All checks passed successfully." in capsys.readouterr().out


def test_main_without_arguments_exits_1(monkeypatch, capsys):
    """main() exits with code 1 when no files are passed."""
    monkeypatch.setattr(sys, "argv", ["format_yaml"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    assert "Incorrect usage" in capsys.readouterr().out


def test_main_missing_file_exits_1(monkeypatch, tmp_path, capsys):
    """main() exits with code 1 when a file does not exist."""
    missing = str(tmp_path / "nope.yaml")
    monkeypatch.setattr(sys, "argv", ["format_yaml", missing])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    assert "does not exist" in capsys.readouterr().out
