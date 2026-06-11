# tests/test_bump_year.py

import argparse
import datetime
import logging
import sys

import pytest

import bump_year.main as bump_year_main
from bump_year.main import collect_markdown_files, configure_logger, update_markdown_footers

CURRENT_YEAR = datetime.datetime.now().year


def test_parse_arguments_defaults(monkeypatch):
    """parse_arguments returns the default markdown files and INFO level."""
    monkeypatch.setattr(sys, "argv", ["bump_year"])
    args = bump_year_main.parse_arguments()
    assert "README.md" in args.md_files
    assert "LICENSE" in args.md_files
    assert args.md_dir is None
    assert args.log_level == "INFO"


def test_parse_arguments_custom_values(monkeypatch):
    """parse_arguments honors explicit --md-files, --md-dir and --log-level."""
    monkeypatch.setattr(
        sys,
        "argv",
        ["bump_year", "--md-files", "A.md", "B.md", "--md-dir", "docs", "--log-level", "DEBUG"],
    )
    args = bump_year_main.parse_arguments()
    assert args.md_files == ["A.md", "B.md"]
    assert args.md_dir == "docs"
    assert args.log_level == "DEBUG"


def test_configure_logger_invalid_level_raises(tmp_path, monkeypatch):
    """An unknown log level raises ValueError."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="Invalid log level"):
        configure_logger("VERBOSE")


def test_configure_logger_sets_handlers(tmp_path, monkeypatch):
    """A valid level configures file and console handlers."""
    monkeypatch.chdir(tmp_path)
    configure_logger("DEBUG")
    assert bump_year_main.logger.level == logging.DEBUG
    assert len(bump_year_main.logger.handlers) == 2


def test_update_footer_replaces_previous_year(tmp_path):
    """The footer containing last year is bumped to the current year."""
    md_file = tmp_path / "README.md"
    md_file.write_text(f"# Title\n\nSome text.\n\n© {CURRENT_YEAR - 1} Quipux\n", encoding="utf-8")
    update_markdown_footers([str(md_file)], CURRENT_YEAR)
    content = md_file.read_text(encoding="utf-8")
    assert f"© {CURRENT_YEAR} Quipux" in content
    assert str(CURRENT_YEAR - 1) not in content


def test_update_footer_only_touches_last_matching_line(tmp_path):
    """Only the footer (last line with the previous year) is updated."""
    md_file = tmp_path / "README.md"
    md_file.write_text(
        f"Copyright {CURRENT_YEAR - 1} header\n\nbody\n\n© {CURRENT_YEAR - 1} Footer\n",
        encoding="utf-8",
    )
    update_markdown_footers([str(md_file)], CURRENT_YEAR)
    lines = md_file.read_text(encoding="utf-8").splitlines()
    assert lines[0] == f"Copyright {CURRENT_YEAR - 1} header"
    assert lines[-1] == f"© {CURRENT_YEAR} Footer"


def test_update_footer_skips_file_already_at_current_year(tmp_path, caplog):
    """A footer already at the current year is left untouched."""
    md_file = tmp_path / "README.md"
    original = f"© {CURRENT_YEAR} Quipux\n"
    md_file.write_text(original, encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="bump_year.main"):
        update_markdown_footers([str(md_file)], CURRENT_YEAR)
    assert md_file.read_text(encoding="utf-8") == original
    assert "No footer with a year to update" in caplog.text


def test_update_footer_skips_file_without_years(tmp_path):
    """A file without any year is skipped."""
    md_file = tmp_path / "README.md"
    original = "no dates here\n"
    md_file.write_text(original, encoding="utf-8")
    update_markdown_footers([str(md_file)], CURRENT_YEAR)
    assert md_file.read_text(encoding="utf-8") == original


def test_update_footer_warns_on_missing_file(tmp_path, caplog):
    """A nonexistent file logs a warning and is skipped."""
    with caplog.at_level(logging.WARNING, logger="bump_year.main"):
        update_markdown_footers([str(tmp_path / "missing.md")], CURRENT_YEAR)
    assert "does not exist. Skipping." in caplog.text


def test_update_footer_logs_read_errors(tmp_path, caplog):
    """An unreadable file logs an error and does not raise."""
    md_file = tmp_path / "README.md"
    md_file.write_text(f"© {CURRENT_YEAR - 1}\n", encoding="utf-8")
    md_file.chmod(0o000)
    try:
        with caplog.at_level(logging.ERROR, logger="bump_year.main"):
            update_markdown_footers([str(md_file)], CURRENT_YEAR)
    finally:
        md_file.chmod(0o644)
    assert "Error reading" in caplog.text


def test_update_footer_logs_write_errors(tmp_path, caplog):
    """A read-only file logs a write error and does not raise."""
    md_file = tmp_path / "README.md"
    md_file.write_text(f"© {CURRENT_YEAR - 1}\n", encoding="utf-8")
    md_file.chmod(0o444)
    try:
        with caplog.at_level(logging.ERROR, logger="bump_year.main"):
            update_markdown_footers([str(md_file)], CURRENT_YEAR)
    finally:
        md_file.chmod(0o644)
    assert "Error writing to" in caplog.text


def test_collect_markdown_files_without_directory():
    """Without md_dir the provided file list is returned as is."""
    collected = collect_markdown_files(["README.md", "CONTRIBUTING.md"])
    assert set(collected) == {"README.md", "CONTRIBUTING.md"}


def test_collect_markdown_files_walks_directory(tmp_path):
    """md_dir is walked recursively collecting only markdown files."""
    (tmp_path / "x.md").write_text("x", encoding="utf-8")
    (tmp_path / "UPPER.MD").write_text("u", encoding="utf-8")
    (tmp_path / "z.txt").write_text("z", encoding="utf-8")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "y.md").write_text("y", encoding="utf-8")

    collected = collect_markdown_files(["base.md"], str(tmp_path))
    assert "base.md" in collected
    assert str(tmp_path / "x.md") in collected
    assert str(tmp_path / "UPPER.MD") in collected
    assert str(sub / "y.md") in collected
    assert str(tmp_path / "z.txt") not in collected


def test_collect_markdown_files_warns_on_missing_directory(tmp_path, caplog):
    """A nonexistent md_dir logs a warning and only files are returned."""
    with caplog.at_level(logging.WARNING, logger="bump_year.main"):
        collected = collect_markdown_files(["base.md"], str(tmp_path / "missing"))
    assert collected == ["base.md"]
    assert "does not exist. Skipping." in caplog.text


def test_main_updates_collected_files(tmp_path, monkeypatch):
    """main() bumps the footer of the files referenced by the module-level args."""
    md_file = tmp_path / "README.md"
    md_file.write_text(f"© {CURRENT_YEAR - 1} Quipux\n", encoding="utf-8")
    monkeypatch.setattr(
        bump_year_main,
        "args",
        argparse.Namespace(md_files=[str(md_file)], md_dir=None),
        raising=False,
    )
    bump_year_main.main()
    assert f"© {CURRENT_YEAR} Quipux" in md_file.read_text(encoding="utf-8")


def test_main_logs_error_when_no_files(monkeypatch, caplog):
    """main() logs an error when no markdown files are collected."""
    monkeypatch.setattr(
        bump_year_main,
        "args",
        argparse.Namespace(md_files=[], md_dir=None),
        raising=False,
    )
    with caplog.at_level(logging.ERROR, logger="bump_year.main"):
        bump_year_main.main()
    assert "No Markdown files specified" in caplog.text
