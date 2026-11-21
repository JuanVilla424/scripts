# tests/test_control_commit.py

import subprocess
import sys

import pytest

from control_commit.main import (
    add_icon_to_commit_message,
    amend_commit,
    configure_logger,
    has_square_brackets,
    main,
    read_head_commit_message,
    validate_commit_message,
)

REWORD_TEMPLATE = (
    "# Please enter the commit message for your changes. Lines starting\n"
    "# with '#' will be ignored, and an empty message aborts the commit.\n"
)


def _git(*args):
    subprocess.run(["git", *args], check=True, capture_output=True)


@pytest.fixture
def commit_msg_repo(tmp_path, monkeypatch):
    """Creates a real temporary git repo, chdirs into it, and returns a function that
    records a commit with the given message as HEAD (the commit a pre-push validates)."""
    monkeypatch.chdir(tmp_path)
    _git("init", "-q")
    _git("config", "user.email", "test@example.com")
    _git("config", "user.name", "test")
    _git("config", "commit.gpgsign", "false")

    def write(message):
        _git("commit", "-q", "--allow-empty", "--no-verify", "-m", message)

    return write


def test_configure_logger_invalid_level_raises(tmp_path, monkeypatch):
    """An unknown log level raises ValueError."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="Invalid log level"):
        configure_logger("TRACE")


@pytest.mark.parametrize(
    "message",
    [
        "feat: add feature",
        "fix(core): handle pagination",
        "chore(api-v2): bump deps",
        "refactor: extract provider pattern",
        "docs: update readme",
    ],
)
def test_validate_commit_message_valid(message, tmp_path, monkeypatch):
    """Well-formed conventional commit messages are valid."""
    monkeypatch.chdir(tmp_path)
    assert validate_commit_message(message) is True


@pytest.mark.parametrize(
    "message",
    [
        "feat: Add feature",  # description must start lowercase
        "feature: add x",  # unknown type
        "feat:missing space",  # missing space after colon
        "feat(Core): add x",  # scope must be lowercase
        "random text",  # no structure at all
    ],
)
def test_validate_commit_message_invalid(message, tmp_path, monkeypatch):
    """Malformed commit messages are rejected."""
    monkeypatch.chdir(tmp_path)
    assert validate_commit_message(message) is False


def test_validate_commit_message_allows_bump_version():
    """Version bump commits bypass the conventional structure."""
    assert validate_commit_message("Bump version: 1.0.0 → 1.0.1") is True


@pytest.mark.parametrize(
    ("commit_type", "icon"),
    [("feat", "✨"), ("fix", "🐛"), ("docs", "📝"), ("chore", "🔧"), ("test", "✅")],
)
def test_add_icon_to_commit_message(commit_type, icon):
    """The icon matching the commit type is prepended."""
    message = f"{commit_type}: do something"
    assert add_icon_to_commit_message(commit_type, message) == f"{icon} {message}"


def test_add_icon_keeps_existing_icon():
    """A message that already starts with its icon is not changed."""
    message = "✨ feat: do something"
    assert add_icon_to_commit_message("feat", message) == message


def test_add_icon_unknown_type_returns_message():
    """An unknown commit type has no icon mapping and leaves the message as is."""
    assert add_icon_to_commit_message("wip", "wip: stuff") == "wip: stuff"


def test_has_square_brackets():
    """Square brackets detection for candidate markers."""
    assert has_square_brackets("feat: add x [patch candidate]") is True
    assert has_square_brackets("feat: add x") is False


def test_read_head_commit_message_returns_head_stripped(commit_msg_repo):
    """The message of the HEAD commit is returned stripped."""
    commit_msg_repo("  feat: add feature  ")
    assert read_head_commit_message() == "feat: add feature"


def test_read_head_commit_message_outside_a_repo_exits_1(tmp_path, monkeypatch):
    """Without a git repository there is no HEAD to validate: exits with code 1."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc_info:
        read_head_commit_message()
    assert exc_info.value.code == 1


def test_main_accepts_a_merge_commit_with_the_git_default_message(commit_msg_repo, monkeypatch):
    """A merge commit (two parents) carries the message git generates ("Merge branch ...").
    It is not the author's conventional commit, so it is accepted as it is, never blocked."""
    monkeypatch.setattr(sys, "argv", ["control_commit"])
    commit_msg_repo("✨ feat: base")
    _git("checkout", "-q", "-b", "side")
    commit_msg_repo("✨ feat: side work")
    _git("checkout", "-q", "-")
    commit_msg_repo("✨ feat: main work")
    _git("merge", "-q", "--no-edit", "--no-verify", "side")
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0


def test_main_validates_head_not_a_stale_commit_editmsg(commit_msg_repo, monkeypatch, tmp_path):
    """After a rebase with reword, .git/COMMIT_EDITMSG keeps the editor template ('#'
    lines) while HEAD is clean. The pre-push check must judge HEAD, the commit pushed."""
    monkeypatch.setattr(sys, "argv", ["control_commit"])
    commit_msg_repo("✨ feat: add feature")
    (tmp_path / ".git" / "COMMIT_EDITMSG").write_text(
        "✨ feat: add feature\n\n" + REWORD_TEMPLATE, encoding="utf-8"
    )
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0


def test_amend_commit_invokes_git(mocker):
    """The commit is amended via git with the new message."""
    mock_run = mocker.patch("control_commit.main.subprocess.run")
    amend_commit("✨ feat: add feature")
    mock_run.assert_called_once_with(
        ["git", "commit", "--amend", "-m", "✨ feat: add feature"], check=True
    )


def test_amend_commit_failure_exits_1(mocker):
    """A git failure while amending exits with code 1."""
    mocker.patch(
        "control_commit.main.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "git"),
    )
    with pytest.raises(SystemExit) as exc_info:
        amend_commit("✨ feat: add feature")
    assert exc_info.value.code == 1


def test_main_bump_version_message_exits_0(commit_msg_repo, monkeypatch):
    """A version bump commit message is accepted right away."""
    monkeypatch.setattr(sys, "argv", ["control_commit"])
    commit_msg_repo("🔖 Bump version: 1.1.19 → 1.1.20")
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0


def test_main_iconed_valid_message_exits_0(commit_msg_repo, monkeypatch):
    """A message that already carries its icon and is valid exits 0."""
    monkeypatch.setattr(sys, "argv", ["control_commit"])
    commit_msg_repo("✨ feat: add feature")
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0


def test_main_iconed_invalid_message_exits_1(commit_msg_repo, monkeypatch):
    """A message with icon but invalid structure aborts the commit."""
    monkeypatch.setattr(sys, "argv", ["control_commit"])
    commit_msg_repo("✨ feat: Broken Description")
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1


def test_main_valid_message_without_icon_amends_and_exits_1(commit_msg_repo, monkeypatch, mocker):
    """A valid message without icon gets amended with the icon and aborts for review."""
    monkeypatch.setattr(sys, "argv", ["control_commit"])
    mock_amend = mocker.patch("control_commit.main.amend_commit")
    commit_msg_repo("feat: add feature")
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    mock_amend.assert_called_once_with("✨ feat: add feature")


def test_main_invalid_message_without_icon_exits_1(commit_msg_repo, monkeypatch, mocker):
    """An invalid message without icon aborts without amending."""
    monkeypatch.setattr(sys, "argv", ["control_commit"])
    mock_amend = mocker.patch("control_commit.main.amend_commit")
    commit_msg_repo("random text")
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    mock_amend.assert_not_called()
