# tests/test_validate_container_names.py

import sys

import pytest

from validate_container_names.main import validate_filename, main


@pytest.mark.parametrize(
    "filename",
    [
        "ContainerGESTIONATENCIONBACKPROD.yml",
        "ContainerABPROD.yml",
        "ContainerAB12TEST.yml",
        "ContainerX9DEV.yml",
    ],
)
def test_validate_filename_valid(filename, capsys):
    """Valid container template names pass validation and print an [OK] line."""
    assert validate_filename(filename) is True
    captured = capsys.readouterr()
    assert "[OK]" in captured.out


@pytest.mark.parametrize(
    "filename",
    [
        "Containerab12PROD.yml",  # lowercase suite/app
        "ContainerABCD.yml",  # missing env suffix
        "ContainerAPROD.yml",  # suite+app shorter than 2 chars
        "ContainerAB-CDPROD.yml",  # hyphen not allowed
        "ContainerABPROD.yaml",  # wrong extension
        "containerABPROD.yml",  # lowercase prefix
        "ABPROD.yml",  # missing Container prefix
    ],
)
def test_validate_filename_invalid(filename, capsys):
    """Invalid names fail validation and print the [ERROR] explanation."""
    assert validate_filename(filename) is False
    captured = capsys.readouterr()
    assert "[ERROR]" in captured.out
    assert "does not follow the naming convention" in captured.out


def test_validate_filename_uses_basename(capsys):
    """Validation applies to the basename, ignoring directories in the path."""
    assert validate_filename("templates/clients/ContainerABTEST.yml") is True
    captured = capsys.readouterr()
    assert "suite+app: 'AB'" in captured.out
    assert "env: 'TEST'" in captured.out


def test_main_without_arguments_exits_1(monkeypatch, capsys):
    """main() exits with code 1 when no files are passed."""
    monkeypatch.setattr(sys, "argv", ["validate_container_names"])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    assert "Incorrect usage" in capsys.readouterr().out


def test_main_all_valid_exits_0(monkeypatch, capsys):
    """main() exits with code 0 when every file passes validation."""
    monkeypatch.setattr(
        sys, "argv", ["validate_container_names", "ContainerABPROD.yml", "ContainerCDTEST.yml"]
    )
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    assert "All 2 file(s) passed naming validation" in capsys.readouterr().out


def test_main_with_invalid_file_exits_1(monkeypatch, capsys):
    """main() exits with code 1 and lists the offending files."""
    monkeypatch.setattr(
        sys, "argv", ["validate_container_names", "ContainerABPROD.yml", "badname.yml"]
    )
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "[FAIL] 1 file(s) with invalid names: badname.yml" in captured.out
