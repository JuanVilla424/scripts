# tests/test_commit_msg_version_bump.py

import subprocess
import sys
from unittest import mock

import pytest

import commit_msg_version_bump.main as cmvb
from commit_msg_version_bump.main import (
    add_icon_and_prepare_commit_message,
    amend_commit,
    bump_version,
    configure_logger,
    determine_version_bump,
    get_current_version,
    get_latest_commit_message,
    get_new_version,
    parse_arguments,
    stage_changes,
)


def _write_pyproject(tmp_path, version='version = "1.2.3"'):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f"[tool.poetry]\nname = 'x'\n{version}\n", encoding="utf-8")
    return str(pyproject)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("feat: add feature [minor candidate]", "minor"),
        ("fix: solve bug [patch candidate]", "patch"),
        ("refactor: rework core [major candidate]", "major"),
        ("fix: solve bug [Patch Candidate]", "patch"),  # case-insensitive
        ("fix: [patch candidate] not at the end", None),
        ("fix: solve bug", None),
    ],
)
def test_determine_version_bump(message, expected):
    """The candidate keyword is only honored at the end of the message."""
    assert determine_version_bump(message) == expected


def test_parse_arguments_defaults(monkeypatch):
    """parse_arguments defaults to INFO log level."""
    monkeypatch.setattr(sys, "argv", ["commit_msg_version_bump"])
    assert parse_arguments().log_level == "INFO"


def test_configure_logger_invalid_level_raises(tmp_path, monkeypatch):
    """An unknown log level raises ValueError."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="Invalid log level"):
        configure_logger("LOUD")


def test_get_latest_commit_message(mocker):
    """The latest commit subject is returned stripped."""
    mocker.patch(
        "commit_msg_version_bump.main.subprocess.run",
        return_value=mock.Mock(stdout="✨ feat: add feature\n"),
    )
    assert get_latest_commit_message() == "✨ feat: add feature"


def test_get_latest_commit_message_failure_exits_1(mocker):
    """A git failure exits with code 1."""
    mocker.patch(
        "commit_msg_version_bump.main.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "git", stderr="boom"),
    )
    with pytest.raises(SystemExit) as exc_info:
        get_latest_commit_message()
    assert exc_info.value.code == 1


def test_get_current_version_reads_pyproject(tmp_path):
    """The poetry version is read from pyproject.toml."""
    assert get_current_version(_write_pyproject(tmp_path)) == "1.2.3"


def test_get_current_version_missing_file_exits_1(tmp_path):
    """A missing pyproject.toml exits with code 1."""
    with pytest.raises(SystemExit) as exc_info:
        get_current_version(str(tmp_path / "missing.toml"))
    assert exc_info.value.code == 1


def test_get_current_version_invalid_toml_exits_1(tmp_path):
    """An unparsable pyproject.toml exits with code 1."""
    bad = tmp_path / "pyproject.toml"
    bad.write_text(":::: not toml ::::", encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        get_current_version(str(bad))
    assert exc_info.value.code == 1


def test_get_current_version_missing_key_exits_1(tmp_path):
    """A pyproject.toml without tool.poetry.version exits with code 1."""
    bad = tmp_path / "pyproject.toml"
    bad.write_text("[tool.other]\nname = 'x'\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        get_current_version(str(bad))
    assert exc_info.value.code == 1


def test_get_new_version_reads_pyproject(tmp_path):
    """The bumped version is read back from pyproject.toml."""
    assert get_new_version(_write_pyproject(tmp_path, 'version = "1.3.0"')) == "1.3.0"


def test_get_new_version_missing_file_exits_1(tmp_path):
    """A missing pyproject.toml exits with code 1."""
    with pytest.raises(SystemExit) as exc_info:
        get_new_version(str(tmp_path / "missing.toml"))
    assert exc_info.value.code == 1


def test_add_icon_and_prepare_commit_message():
    """The bump commit message carries the bookmark icon and both versions."""
    assert add_icon_and_prepare_commit_message("1.0.0", "1.1.0") == "🔖 Bump version: 1.0.0 → 1.1.0"


def test_bump_version_invokes_bump2version(mocker):
    """bump2version is invoked with the requested part."""
    mock_run = mocker.patch("commit_msg_version_bump.main.subprocess.run")
    bump_version("patch")
    mock_run.assert_called_once_with(["bump2version", "patch"], check=True, encoding="utf-8")


def test_bump_version_failure_exits_1(mocker):
    """A bump2version failure exits with code 1."""
    mocker.patch(
        "commit_msg_version_bump.main.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "bump2version"),
    )
    with pytest.raises(SystemExit) as exc_info:
        bump_version("patch")
    assert exc_info.value.code == 1


def test_stage_changes_invokes_git_add(mocker):
    """pyproject.toml is staged for the amended commit."""
    mock_run = mocker.patch("commit_msg_version_bump.main.subprocess.run")
    stage_changes()
    mock_run.assert_called_once_with(["git", "add", "pyproject.toml"], check=True, encoding="utf-8")


def test_stage_changes_failure_exits_1(mocker):
    """A git add failure exits with code 1."""
    mocker.patch(
        "commit_msg_version_bump.main.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "git"),
    )
    with pytest.raises(SystemExit) as exc_info:
        stage_changes()
    assert exc_info.value.code == 1


def test_amend_commit_invokes_git(mocker):
    """The commit is amended with the bump message."""
    mock_run = mocker.patch("commit_msg_version_bump.main.subprocess.run")
    amend_commit("🔖 Bump version: 1.0.0 → 1.0.1")
    mock_run.assert_called_once_with(
        ["git", "commit", "--amend", "-m", "🔖 Bump version: 1.0.0 → 1.0.1"],
        check=True,
        encoding="utf-8",
    )


def test_amend_commit_failure_exits_1(mocker):
    """A git amend failure exits with code 1."""
    mocker.patch(
        "commit_msg_version_bump.main.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "git"),
    )
    with pytest.raises(SystemExit) as exc_info:
        amend_commit("🔖 Bump version: 1.0.0 → 1.0.1")
    assert exc_info.value.code == 1


def test_main_with_candidate_bumps_and_exits_1(tmp_path, monkeypatch, mocker):
    """A candidate keyword triggers bump, stage and amend, then aborts the push."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["commit_msg_version_bump"])
    mocker.patch(
        "commit_msg_version_bump.main.get_latest_commit_message",
        return_value="fix: solve bug [patch candidate]",
    )
    mocker.patch("commit_msg_version_bump.main.get_current_version", return_value="1.0.0")
    mock_bump = mocker.patch("commit_msg_version_bump.main.bump_version")
    mocker.patch("commit_msg_version_bump.main.get_new_version", return_value="1.0.1")
    mock_stage = mocker.patch("commit_msg_version_bump.main.stage_changes")
    mock_amend = mocker.patch("commit_msg_version_bump.main.amend_commit")

    with pytest.raises(SystemExit) as exc_info:
        cmvb.main()

    assert exc_info.value.code == 1
    mock_bump.assert_called_once_with("patch")
    mock_stage.assert_called_once()
    mock_amend.assert_called_once_with("🔖 Bump version: 1.0.0 → 1.0.1")


def test_main_without_candidate_does_nothing(tmp_path, monkeypatch, mocker):
    """Without a candidate keyword no bump happens and main returns normally."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["commit_msg_version_bump"])
    mocker.patch(
        "commit_msg_version_bump.main.get_latest_commit_message",
        return_value="fix: solve bug",
    )
    mock_bump = mocker.patch("commit_msg_version_bump.main.bump_version")

    cmvb.main()

    mock_bump.assert_not_called()
