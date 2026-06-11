# tests/test_generate_changelog.py

import logging
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime, timezone

import pytest

import generate_changelog.main as gcl
from generate_changelog.main import (
    compare_versions,
    fetch_tags,
    generate_changelog_entry,
    generate_full_changelog,
    get_all_commits,
    get_commits_between_tags,
    get_commits_since_last_tag,
    get_sorted_tags,
    get_tag_date,
    get_tag_dates,
    is_noise_commit,
    parse_arguments,
    parse_commits,
    parse_version,
    update_changelog,
)

TODAY_UTC = datetime.now(timezone.utc).strftime("%Y-%m-%d")


def test_parse_arguments_defaults(monkeypatch):
    """parse_arguments defaults to INFO log level."""
    monkeypatch.setattr(sys, "argv", ["generate_changelog"])
    assert parse_arguments().log_level == "INFO"


def test_configure_logger_invalid_level_raises(tmp_path, monkeypatch):
    """An unknown log level raises ValueError."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="Invalid log level"):
        gcl.configure_logger("CHATTY")


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("v1.2.3", (1, 2, 3)),
        ("1.0.8-test", (1, 0, 8)),
        ("v10.20.30", (10, 20, 30)),
        ("garbage", (0, 0, 0)),
        ("1.2", (0, 0, 0)),
    ],
)
def test_parse_version(version, expected):
    """Version strings are parsed into numeric tuples, invalid ones become zeros."""
    assert parse_version(version) == expected


@pytest.mark.parametrize(
    ("v1", "v2", "expected"),
    [
        ("v2.0.0", "v1.9.9", 1),
        ("v1.0.0", "v1.0.1", -1),
        ("1.2.3", "1.2.3", 0),
        ("v1.10.0", "v1.9.0", 1),  # numeric, not lexicographic
        ("v1.0.10", "v1.0.9", 1),
        ("v1.1.0", "v1.2.0", -1),
    ],
)
def test_compare_versions(v1, v2, expected):
    """Semantic comparison across major, minor and patch."""
    assert compare_versions(v1, v2) == expected


@pytest.mark.parametrize(
    ("commit", "expected"),
    [
        ("🔖 Bump version: 1.0.0 → 1.0.1", True),
        ("Merge branch 'dev' into testing", True),
        ("Merge pull request #12 from fork/dev", True),
        ("feat: add feature", False),
    ],
)
def test_is_noise_commit(commit, expected):
    """Bump and merge commits are noise; regular commits are not."""
    assert is_noise_commit(commit) is expected


def test_parse_commits_categorizes_by_type():
    """Commits are categorized, emojis stripped, noise skipped, extras collected."""
    commits = [
        "✨ feat(core): add support [minor candidate]",
        "fix: solve bug",
        "random words",
        "Merge branch 'dev'",
    ]
    changelog, non_conforming = parse_commits(commits)
    assert changelog["### Features"] == ["- **core**: add support (`minor candidate`)"]
    assert changelog["### Bug Fixes"] == ["- solve bug"]
    assert "### Chores" not in changelog  # empty sections are dropped
    assert non_conforming == ["random words"]


def test_parse_commits_empty_input():
    """No commits produce an empty changelog and no leftovers."""
    changelog, non_conforming = parse_commits([])
    assert changelog == {}
    assert non_conforming == []


def test_generate_changelog_entry_with_date():
    """The entry renders header, sections and other changes."""
    entry = generate_changelog_entry(
        "1.1.0",
        {"### Features": ["- **core**: add support"]},
        ["mystery commit"],
        "2026-01-05",
    )
    assert entry.startswith("## [1.1.0] - 2026-01-05\n")
    assert "### Features\n- **core**: add support\n" in entry
    assert "### Other Changes\n- mystery commit\n" in entry


def test_generate_changelog_entry_defaults_to_today():
    """Without an explicit date the entry is stamped with today (UTC)."""
    entry = generate_changelog_entry("1.0.0", {}, [])
    assert entry.startswith(f"## [1.0.0] - {TODAY_UTC}")


def test_generate_full_changelog_orders_latest_first_and_skips_empty():
    """Versions are rendered newest first; tagless versions without commits are skipped."""
    commits_dict = OrderedDict(
        [("1.0.0", ["feat: first"]), ("1.1.0", ["fix: second"]), ("2.0.0", [])]
    )
    tag_dates = {"1.0.0": "2026-01-01", "1.1.0": "2026-02-01"}
    content = generate_full_changelog(commits_dict, tag_dates)
    assert "## [2.0.0]" not in content
    assert content.index("## [1.1.0] - 2026-02-01") < content.index("## [1.0.0] - 2026-01-01")


def test_fetch_tags_invokes_git(mocker):
    """Tags are fetched from the remote."""
    mock_output = mocker.patch("generate_changelog.main.subprocess.check_output")
    fetch_tags()
    mock_output.assert_called_once_with(["git", "fetch", "--tags"])


def test_fetch_tags_failure_only_warns(mocker, caplog):
    """A fetch failure logs a warning and does not raise."""
    mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        side_effect=subprocess.CalledProcessError(1, "git"),
    )
    with caplog.at_level(logging.WARNING, logger="generate_changelog.main"):
        fetch_tags()
    assert "Could not fetch Git tags" in caplog.text


def test_get_tag_date(mocker):
    """The tag date is extracted from the git log output."""
    mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        return_value="2026-01-02 10:00:00 -0500\n",
    )
    assert get_tag_date("v1.0.0") == "2026-01-02"


def test_get_tag_date_failure_falls_back_to_today(mocker):
    """A git failure falls back to today's date."""
    mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        side_effect=subprocess.CalledProcessError(1, "git"),
    )
    assert get_tag_date("v1.0.0") == TODAY_UTC


def test_get_sorted_tags_filters_and_sorts_semantically(mocker):
    """Only vX.Y.Z tags are kept, sorted numerically ascending."""
    mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        return_value="v1.0.10\nv1.0.2\nv2.0.0\nfoo\nv1.0.2-test\n",
    )
    assert get_sorted_tags() == ["v1.0.2", "v1.0.10", "v2.0.0"]


def test_get_sorted_tags_without_semantic_tags_returns_empty(mocker, caplog):
    """Without semantic tags an empty list is returned with a warning."""
    mocker.patch("generate_changelog.main.subprocess.check_output", return_value="foo\nbar\n")
    with caplog.at_level(logging.WARNING, logger="generate_changelog.main"):
        assert get_sorted_tags() == []
    assert "No semantic Git tags found" in caplog.text


def test_get_sorted_tags_failure_returns_empty(mocker):
    """A git failure returns an empty list."""
    mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        side_effect=subprocess.CalledProcessError(1, "git"),
    )
    assert get_sorted_tags() == []


def test_get_commits_between_tags(mocker):
    """Commits between two tags are listed using the tag range."""
    mock_output = mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        return_value=b"feat: a\nfix: b\n",
    )
    assert get_commits_between_tags("v1.0.0", "v1.1.0") == ["feat: a", "fix: b"]
    mock_output.assert_called_once_with(["git", "log", "v1.0.0..v1.1.0", "--pretty=format:%s"])


def test_get_commits_between_tags_without_old_tag(mocker):
    """Without an old tag, every commit up to the new tag is listed."""
    mock_output = mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        return_value=b"feat: a\n",
    )
    assert get_commits_between_tags("", "v1.0.0") == ["feat: a"]
    mock_output.assert_called_once_with(["git", "log", "v1.0.0", "--pretty=format:%s"])


def test_get_commits_between_tags_failure_returns_empty(mocker):
    """A git failure returns an empty list."""
    mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        side_effect=subprocess.CalledProcessError(1, "git"),
    )
    assert get_commits_between_tags("v1.0.0", "v1.1.0") == []


def test_get_commits_since_last_tag_without_tags(mocker):
    """Without tags, all repository commits are returned."""
    mock_output = mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        return_value=b"feat: a\nfix: b\n",
    )
    assert get_commits_since_last_tag([]) == ["feat: a", "fix: b"]
    mock_output.assert_called_once_with(["git", "log", "--pretty=format:%s"])


def test_get_commits_since_last_tag_uses_latest_tag(mocker):
    """With tags, only commits after the latest tag are returned."""
    mock_output = mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        return_value=b"fix: pending\n",
    )
    assert get_commits_since_last_tag(["v0.9.0", "v1.0.0"]) == ["fix: pending"]
    mock_output.assert_called_once_with(["git", "log", "v1.0.0..HEAD", "--pretty=format:%s"])


def test_get_commits_since_last_tag_failures_return_empty(mocker):
    """Git failures return an empty list on both paths."""
    mocker.patch(
        "generate_changelog.main.subprocess.check_output",
        side_effect=subprocess.CalledProcessError(1, "git"),
    )
    assert get_commits_since_last_tag([]) == []
    assert get_commits_since_last_tag(["v1.0.0"]) == []


def test_get_all_commits_chains_tag_ranges(mocker):
    """Each tag collects the commits since the previous one, keyed without 'v'."""
    mock_between = mocker.patch(
        "generate_changelog.main.get_commits_between_tags",
        side_effect=[["feat: a"], ["fix: b"]],
    )
    commits_dict = get_all_commits(["v1.0.0", "v1.1.0"])
    assert list(commits_dict.keys()) == ["1.0.0", "1.1.0"]
    assert commits_dict["1.0.0"] == ["feat: a"]
    assert commits_dict["1.1.0"] == ["fix: b"]
    assert mock_between.call_args_list[0].args == ("", "v1.0.0")
    assert mock_between.call_args_list[1].args == ("v1.0.0", "v1.1.0")


def test_get_tag_dates_includes_unreleased(mocker):
    """Tag dates are mapped without the 'v' prefix plus an Unreleased entry."""
    mocker.patch("generate_changelog.main.get_tag_date", return_value="2026-01-01")
    dates = get_tag_dates(["v1.0.0"])
    assert dates["1.0.0"] == "2026-01-01"
    assert dates["Unreleased"] == TODAY_UTC


def test_update_changelog_creates_missing_file(tmp_path, monkeypatch):
    """A missing CHANGELOG.md is created with the new content."""
    monkeypatch.chdir(tmp_path)
    assert update_changelog("## [1.0.0] - 2026-01-01\n") is True
    assert (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8") == "## [1.0.0] - 2026-01-01\n"


def test_update_changelog_skips_identical_content(tmp_path, monkeypatch):
    """Whitespace-only differences do not rewrite the changelog."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "CHANGELOG.md").write_text("## [1.0.0] - 2026-01-01\n\n- a\n", encoding="utf-8")
    assert update_changelog("## [1.0.0]   - 2026-01-01\n- a") is False


def test_update_changelog_overwrites_on_changes(tmp_path, monkeypatch):
    """Real content changes overwrite the existing changelog."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "CHANGELOG.md").write_text("## [1.0.0] - 2026-01-01\n", encoding="utf-8")
    assert update_changelog("## [1.1.0] - 2026-02-01\n") is True
    assert "1.1.0" in (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")


def test_update_changelog_read_error_returns_false(tmp_path, monkeypatch):
    """An unreadable CHANGELOG.md aborts the update returning False."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "CHANGELOG.md").mkdir()  # a directory cannot be read as a file
    assert update_changelog("content") is False


def test_update_changelog_write_error_returns_false(tmp_path, monkeypatch):
    """An unwritable CHANGELOG.md aborts the update returning False."""
    monkeypatch.chdir(tmp_path)
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text("old content\n", encoding="utf-8")
    changelog.chmod(0o444)
    try:
        assert update_changelog("new content\n") is False
    finally:
        changelog.chmod(0o644)


def test_main_generates_and_updates(mocker):
    """main() builds the changelog from tags and hands it to update_changelog."""
    mocker.patch("generate_changelog.main.fetch_tags")
    mocker.patch("generate_changelog.main.get_sorted_tags", return_value=["v1.0.0"])
    mocker.patch(
        "generate_changelog.main.get_tag_dates",
        return_value={"1.0.0": "2026-01-01", "Unreleased": TODAY_UTC},
    )
    mocker.patch(
        "generate_changelog.main.get_all_commits",
        return_value=OrderedDict([("1.0.0", ["feat: first"])]),
    )
    mock_update = mocker.patch("generate_changelog.main.update_changelog", return_value=True)

    gcl.main()

    mock_update.assert_called_once()
    content = mock_update.call_args.args[0]
    assert "## [1.0.0] - 2026-01-01" in content
    assert "- first" in content


def test_main_without_commits_does_not_update(mocker, caplog):
    """main() skips the update when there is nothing to include."""
    mocker.patch("generate_changelog.main.fetch_tags")
    mocker.patch("generate_changelog.main.get_sorted_tags", return_value=["v1.0.0"])
    mocker.patch("generate_changelog.main.get_tag_dates", return_value={"Unreleased": TODAY_UTC})
    mocker.patch(
        "generate_changelog.main.get_all_commits", return_value=OrderedDict([("1.0.0", [])])
    )
    mock_update = mocker.patch("generate_changelog.main.update_changelog")

    with caplog.at_level(logging.INFO, logger="generate_changelog.main"):
        gcl.main()

    mock_update.assert_not_called()
    assert "No commits found" in caplog.text


def test_main_logs_when_no_update_needed(mocker, caplog):
    """main() reports when the changelog content did not change."""
    mocker.patch("generate_changelog.main.fetch_tags")
    mocker.patch("generate_changelog.main.get_sorted_tags", return_value=["v1.0.0"])
    mocker.patch(
        "generate_changelog.main.get_tag_dates",
        return_value={"1.0.0": "2026-01-01", "Unreleased": TODAY_UTC},
    )
    mocker.patch(
        "generate_changelog.main.get_all_commits",
        return_value=OrderedDict([("1.0.0", ["feat: first"])]),
    )
    mocker.patch("generate_changelog.main.update_changelog", return_value=False)

    with caplog.at_level(logging.INFO, logger="generate_changelog.main"):
        gcl.main()

    assert "Changelog was not updated" in caplog.text
