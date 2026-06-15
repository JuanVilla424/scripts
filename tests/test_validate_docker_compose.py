# tests/test_validate_docker_compose.py

import subprocess
import sys

import pytest

from validate_docker_compose.main import format_docker_compose, validate_docker_compose, main


def _write(tmp_path, name, content):
    file_path = tmp_path / name
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def test_format_adds_document_start_marker(tmp_path, capsys):
    """A compose file without '---' gets the marker prepended."""
    file_path = _write(tmp_path, "docker-compose.yml", "services:\n  app:\n    image: x\n")
    format_docker_compose(file_path)
    content = (tmp_path / "docker-compose.yml").read_text(encoding="utf-8")
    assert content.startswith("---\n")
    captured = capsys.readouterr()
    assert "Added '---' at the beginning" in captured.out


def test_format_keeps_existing_marker(tmp_path, capsys):
    """A compose file that already starts with '---' is left as is."""
    file_path = _write(tmp_path, "docker-compose.yml", "---\nservices: {}\n")
    format_docker_compose(file_path)
    content = (tmp_path / "docker-compose.yml").read_text(encoding="utf-8")
    assert content == "---\nservices: {}\n"
    assert "Added '---'" not in capsys.readouterr().out


def test_format_normalizes_line_endings_to_lf(tmp_path):
    """CRLF line endings are rewritten as LF."""
    file_path = tmp_path / "docker-compose.yml"
    file_path.write_bytes(b"---\r\nservices: {}\r\n")
    format_docker_compose(str(file_path))
    assert b"\r" not in file_path.read_bytes()


def test_validate_success(mocker, capsys):
    """A valid compose file prints [OK]."""
    mock_run = mocker.patch("validate_docker_compose.main.subprocess.run")
    validate_docker_compose("docker-compose.yml")
    mock_run.assert_called_once()
    assert "[OK] docker-compose.yml is valid." in capsys.readouterr().out


def test_validate_invalid_compose_exits_1(mocker, capsys):
    """docker compose config failure prints stderr and exits with 1."""
    mocker.patch(
        "validate_docker_compose.main.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "docker", stderr="invalid service"),
    )
    with pytest.raises(SystemExit) as exc_info:
        validate_docker_compose("docker-compose.yml")
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "[ERROR] Error in file docker-compose.yml:" in captured.out
    assert "invalid service" in captured.out


def test_validate_docker_not_installed_exits_1(mocker, capsys):
    """Missing docker binary exits with 1."""
    mocker.patch("validate_docker_compose.main.subprocess.run", side_effect=FileNotFoundError)
    with pytest.raises(SystemExit) as exc_info:
        validate_docker_compose("docker-compose.yml")
    assert exc_info.value.code == 1
    assert "docker compose not found" in capsys.readouterr().out


def test_main_without_arguments_exits_1(monkeypatch, capsys):
    """main() exits with code 1 when no files are passed."""
    monkeypatch.setattr(sys, "argv", ["validate_docker_compose"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    assert "Incorrect usage" in capsys.readouterr().out


def test_main_missing_file_exits_1(monkeypatch, tmp_path, capsys):
    """main() exits with code 1 when a file does not exist."""
    missing = str(tmp_path / "nope.yml")
    monkeypatch.setattr(sys, "argv", ["validate_docker_compose", missing])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    assert "does not exist" in capsys.readouterr().out


def test_main_formats_and_validates_all_files(monkeypatch, tmp_path, mocker, capsys):
    """main() formats and validates every file, then exits 0."""
    mocker.patch("validate_docker_compose.main.subprocess.run")
    file_a = _write(tmp_path, "a.yml", "services: {}\n")
    file_b = _write(tmp_path, "b.yml", "---\nservices: {}\n")
    monkeypatch.setattr(sys, "argv", ["validate_docker_compose", file_a, file_b])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "All checks passed successfully." in captured.out
    assert (tmp_path / "a.yml").read_text(encoding="utf-8").startswith("---\n")
