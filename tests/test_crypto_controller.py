# tests/test_crypto_controller.py

import base64
import os
import json
import sys
from unittest import mock

import pytest
import requests
import shutil
import tempfile
import logging
from logging.handlers import RotatingFileHandler
from unittest.mock import patch, mock_open
from datetime import datetime, timedelta

# Import CryptoController and related functions from main.py
import crypto_controller.main as cc_main
from crypto_controller.main import (
    CryptoController,
    get_key_footprint,
    Footprint,
    CERT_EXPIRATION_YEARS,
    fetch_private_key_password,
    send_expiration_alert,
    _resolve_key_pair_name,
    configure_logger,
    parse_arguments,
)


# Configure logger for the test module
def configure_test_logger(log_level: str = "DEBUG") -> logging.Logger:
    """
    Configures the logger with rotating file handler and console handler for tests.

    Args:
        log_level (str): Logging level (INFO, DEBUG, etc.).

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger("test_crypto_controller")
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    logger.setLevel(numeric_level)

    # File handler with rotation
    file_handler = RotatingFileHandler(
        "test_crypto_controller.log", maxBytes=5 * 1024 * 1024, backupCount=5
    )
    # Console handler
    console_handler = logging.StreamHandler()

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Clear existing handlers to avoid duplicate logs
    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# Initialize the test logger
logger = configure_test_logger("DEBUG")


# Helper function to create dummy PEM files
def create_dummy_pem(path: str, key_type: str = "public") -> None:
    """
    Creates a dummy PEM file for testing purposes.

    Args:
        path (str): Path where the PEM file will be created.
        key_type (str): Type of the key ('public' or 'private').
    """
    if key_type == "public":
        content = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn...\n"
            "-----END PUBLIC KEY-----\n"
        )
    else:
        content = (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            "MIIE6TAbBgkqhkiG9w0BBQMwDgQIoY...\n"
            "-----END ENCRYPTED PRIVATE KEY-----\n"
        )
    with open(path, "w") as f:
        f.write(content)
    logger.debug(f"Created dummy PEM file at {path} as {key_type} key.")


# Fixtures


@pytest.fixture(autouse=True)
def mock_env_variables():
    """
    Automatically mock environment variables for all tests.
    """
    env_vars = {
        "API_URI": "https://api.mocked.com/get_password",
        "API_TOKEN_SECURITY": "mocked_secure_token",
        "API_TIMEOUT": "5",
        "SMTP_SERVER": "smtp.mocked.com",
        "SMTP_PORT": "587",
        "SMTP_USER": "mocked_user@mocked.com",
        "SMTP_PASSWORD": "mocked_password",
        "ALERT_RECIPIENT": "admin@mocked.com",
    }
    with patch.dict(os.environ, env_vars, clear=True):
        yield


@pytest.fixture
def mock_load_dotenv():
    """
    Mock the load_dotenv function to prevent actual loading of .env files.
    """
    with patch("crypto_controller.main.load_dotenv", return_value=None) as mock_ld:
        yield mock_ld


@pytest.fixture
def mock_requests_get():
    """
    Mock the requests.get method for API calls.
    """
    with patch("crypto_controller.main.requests.get") as mock_get:
        mock_response = mock.Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {"value": "secure_pass"}
        mock_get.return_value = mock_response
        yield mock_get


@pytest.fixture
def mock_smtp():
    """
    Mock the smtplib.SMTP class to prevent actual email sending.
    """
    with patch("crypto_controller.main.smtplib.SMTP") as mock_smtp_class:
        yield mock_smtp_class


@pytest.fixture
def temp_cert_vault() -> str:
    """
    Creates a temporary directory to simulate the certificate vault.
    Cleans up after the test.

    Yields:
        str: Path to the temporary certificate vault.
    """
    vault = tempfile.mkdtemp()
    logger.debug(f"Created temporary certificate vault at {vault}")
    yield vault
    shutil.rmtree(vault)
    logger.debug(f"Deleted temporary certificate vault at {vault}")


@pytest.fixture
def crypto_controller_fixture(temp_cert_vault: str) -> CryptoController:
    """
    Initializes a CryptoController instance with a temporary vault.

    Args:
        temp_cert_vault (str): Path to the temporary certificate vault.

    Returns:
        CryptoController: Initialized CryptoController instance.
    """
    logger.debug("Initializing CryptoController fixture.")
    return CryptoController(
        cert_location=temp_cert_vault, key_pair_name="test_key_pair", private_key_pass="test_pass"
    )


# Test Cases


def test_env_variables_loaded(mock_load_dotenv, crypto_controller_fixture):
    """
    Test that CryptoController initializes correctly with expected attributes.
    load_dotenv is called at module import time so it cannot be asserted via mock here.
    """
    logger.debug("Testing environment variable loading.")
    assert crypto_controller_fixture.cert_location is not None
    assert crypto_controller_fixture.key_pair_name == "test_key_pair"
    logger.debug("CryptoController initialized correctly.")


def test_create_cert_vault(crypto_controller_fixture, temp_cert_vault):
    """
    Test the creation of the certificate vault with correct permissions.
    """
    logger.debug("Testing certificate vault creation.")
    # Ensure the vault does not exist
    shutil.rmtree(temp_cert_vault, ignore_errors=True)
    logger.debug("Deleted existing certificate vault to test creation.")
    assert not os.path.exists(temp_cert_vault)

    # Create the vault
    crypto_controller_fixture.create_cert_vault()
    logger.debug("Called create_cert_vault method.")

    # Verify the vault creation
    assert os.path.exists(temp_cert_vault)
    logger.debug("Certificate vault exists after creation.")

    # Check permissions (mode 700)
    vault_mode = os.stat(temp_cert_vault).st_mode & 0o777
    logger.debug(f"Certificate vault permissions: {oct(vault_mode)}")
    assert vault_mode == 0o700
    logger.debug("Certificate vault has correct permissions (700).")


def test_encrypt_decrypt(crypto_controller_fixture: CryptoController):
    """
    Test the encrypt and decrypt functionality of CryptoController.
    """
    logger.debug("Testing encrypt and decrypt functionality.")
    # Mock the loaded keys
    with patch.object(
        crypto_controller_fixture, "load_keys", return_value=(mock.Mock(), mock.Mock())
    ) as mock_load_keys:
        public_key_mock = mock.Mock()
        private_key_mock = mock.Mock()
        mock_load_keys.return_value = (public_key_mock, private_key_mock)
        logger.debug("Mocked load_keys to return public and private key mocks.")

        # Mock encryption of AES key with RSA public key
        public_key_mock.encrypt.return_value = b"encrypted_aes_key"
        logger.debug("Mocked public_key.encrypt to return encrypted AES key.")

        # Mock decryption of AES key with RSA private key
        private_key_mock.decrypt.return_value = b"a" * 32  # AES key
        logger.debug("Mocked private_key.decrypt to return AES key.")

        # Create dummy PEM files
        public_key_path = crypto_controller_fixture.public_key_file
        private_key_path = crypto_controller_fixture.private_key_file
        create_dummy_pem(public_key_path, "public")
        create_dummy_pem(private_key_path, "private")
        logger.debug(f"Created dummy PEM files at {public_key_path} and {private_key_path}.")

        # Define plaintext
        plaintext = "Hello, World!"
        logger.debug(f"Defined plaintext: '{plaintext}'")

        # Mock os.urandom to return predictable bytes
        with patch("os.urandom", side_effect=[b"a" * 32, b"b" * 16]):
            encrypted = crypto_controller_fixture.encrypt(plaintext)
            logger.debug(f"Encrypted text: {encrypted}")
            assert isinstance(encrypted, str)
            parts = encrypted.split(":")
            assert len(parts) == 3  # encrypted_aes_key:iv:ciphertext
            logger.debug("Encryption resulted in three parts separated by ':'")

        # Mock base64 decoding
        with patch(
            "base64.b64decode", side_effect=[b"encrypted_aes_key", b"b" * 16, b"ciphertext"]
        ):
            # Mock Cipher for decryption
            with patch("crypto_controller.main.Cipher") as mock_cipher:
                mock_decryptor = mock.Mock()
                mock_decryptor.update.return_value = b"decrypted_text"
                mock_decryptor.finalize.return_value = b""
                mock_cipher.return_value.decryptor.return_value = mock_decryptor
                logger.debug("Mocked Cipher for decryption to return decrypted text.")

                decrypted = crypto_controller_fixture.decrypt(encrypted)
                logger.debug(f"Decrypted text: {decrypted}")
                assert decrypted == "decrypted_text"
                logger.debug("Decryption successful and matches expected output.")


def test_verify_success(crypto_controller_fixture: CryptoController, temp_cert_vault: str, mocker):
    """
    Test that verify returns True when all conditions are met.
    """
    logger.debug("Testing verify method for successful verification.")
    # Create dummy key files
    create_dummy_pem(crypto_controller_fixture.public_key_file, "public")
    create_dummy_pem(crypto_controller_fixture.private_key_file, "private")
    logger.debug(
        f"Created dummy public and private key files at {crypto_controller_fixture.public_key_file} and {crypto_controller_fixture.private_key_file}."
    )

    # Create valid key pair data
    key_pair_data = {
        "public_key_file": crypto_controller_fixture.public_key_file,
        "public_fp_sha1": "dummysha1",
        "public_fp_sha256": "dummysha256",
        "private_key_file": crypto_controller_fixture.private_key_file,
        "private_fp_sha1": "dummysha1",
        "private_fp_sha256": "dummysha256",
        "key_pair_file": crypto_controller_fixture.key_pair_file,
        "creation_date": datetime.now().strftime("%d%m%Y%H%M%S"),
        "expiration_date": (datetime.now() + timedelta(days=365)).strftime("%d%m%Y%H%M%S"),
    }
    logger.debug(f"Created key pair data: {key_pair_data}")

    # Mock encrypt and decrypt so verify() can round-trip without real RSA keys
    mocker.patch.object(
        crypto_controller_fixture, "encrypt", return_value=json.dumps(key_pair_data)
    )
    mocker.patch.object(crypto_controller_fixture, "decrypt", side_effect=lambda x: x)
    # Mock get_key_footprint to return matching footprints
    mocker.patch(
        "crypto_controller.main.get_key_footprint",
        return_value=Footprint("dummysha1", "dummysha256"),
    )

    # Write key pair data to key pair file
    with open(crypto_controller_fixture.key_pair_file, "w") as kp_file:
        kp_file.write(json.dumps(key_pair_data))
        logger.debug(
            f"Wrote key pair data to key pair file at {crypto_controller_fixture.key_pair_file}."
        )

    # Execute verify
    result = crypto_controller_fixture.verify()
    logger.debug(f"Verification result: {result}")
    assert result is True
    logger.debug("Verification successful as expected.")


def test_verify_missing_fields(
    crypto_controller_fixture: CryptoController, temp_cert_vault: str, mocker
):
    """
    Test that verify returns False when key pair data is missing required fields.
    """
    logger.debug("Testing verify method with missing key pair data fields.")
    # Create dummy key files
    create_dummy_pem(crypto_controller_fixture.public_key_file, "public")
    create_dummy_pem(crypto_controller_fixture.private_key_file, "private")
    logger.debug(
        f"Created dummy public and private key files at {crypto_controller_fixture.public_key_file} and {crypto_controller_fixture.private_key_file}."
    )

    # Create incomplete key pair data (missing some fields)
    key_pair_data = {
        "public_key_file": crypto_controller_fixture.public_key_file,
        # Missing 'public_fp_sha1' and other required fields
        "private_key_file": crypto_controller_fixture.private_key_file,
        "key_pair_file": crypto_controller_fixture.key_pair_file,
        "creation_date": datetime.now().strftime("%d%m%Y%H%M%S"),
        "expiration_date": (datetime.now() + timedelta(days=365)).strftime("%d%m%Y%H%M%S"),
    }
    logger.debug(f"Created incomplete key pair data: {key_pair_data}")

    # Mock encrypt and decrypt so verify() can round-trip without real RSA keys
    mocker.patch.object(
        crypto_controller_fixture, "encrypt", return_value=json.dumps(key_pair_data)
    )
    mocker.patch.object(crypto_controller_fixture, "decrypt", side_effect=lambda x: x)

    # Write incomplete key pair data to key pair file
    with open(crypto_controller_fixture.key_pair_file, "w") as kp_file:
        kp_file.write(json.dumps(key_pair_data))
        logger.debug(
            f"Wrote incomplete key pair data to key pair file at {crypto_controller_fixture.key_pair_file}."
        )

    # Execute verify
    result = crypto_controller_fixture.verify()
    logger.debug(f"Verification result with missing fields: {result}")
    assert result is False
    logger.debug("Verification correctly failed due to missing fields.")


def test_create_keys(crypto_controller_fixture: CryptoController, temp_cert_vault: str, mocker):
    """
    Test the creation of RSA key pairs and the key pair file.
    """
    logger.debug("Testing create_keys method.")
    # Ensure key files do not exist
    assert not os.path.exists(crypto_controller_fixture.public_key_file)
    assert not os.path.exists(crypto_controller_fixture.private_key_file)
    assert not os.path.exists(crypto_controller_fixture.key_pair_file)
    logger.debug("Verified that key files do not exist before creation.")

    # Mock the key generation and serialization
    mock_generate_key = mocker.patch("crypto_controller.main.rsa.generate_private_key")
    mock_private_key = mock.Mock()
    mock_public_key = mock.Mock()
    mock_generate_key.return_value = mock_private_key
    mock_private_key.public_key.return_value = mock_public_key
    mock_private_key.private_bytes.return_value = b"encrypted_private_key"
    mock_public_key.public_bytes.return_value = b"public_key"
    logger.debug("Mocked rsa.generate_private_key and key serialization methods.")

    # Mock get_key_footprint to return dummy footprints
    mocker.patch(
        "crypto_controller.main.get_key_footprint",
        return_value=Footprint("dummysha1", "dummysha256"),
    )

    # Mock json.dumps to return a JSON string
    mocker.patch("crypto_controller.main.json.dumps", return_value='{"key": "value"}')

    # Mock the encrypt method to return an encrypted key pair
    mocker.patch.object(crypto_controller_fixture, "encrypt", return_value="encrypted_kp")

    # Execute create_keys
    crypto_controller_fixture.create_keys()
    logger.debug("Called create_keys method.")

    # Verify that key files are created
    assert os.path.exists(crypto_controller_fixture.public_key_file)
    assert os.path.exists(crypto_controller_fixture.private_key_file)
    assert os.path.exists(crypto_controller_fixture.key_pair_file)
    logger.debug("Verified that key files were created successfully.")


def test_get_status(crypto_controller_fixture: CryptoController, mocker, capsys):
    """
    Test the get_status method outputs the correct status information.
    """
    logger.debug("Testing get_status method.")
    # Mock the status methods to return known values
    mocker.patch.object(crypto_controller_fixture, "check_cert_vault_exists", return_value=True)
    mocker.patch.object(crypto_controller_fixture, "verify", return_value=True)
    mocker.patch.object(
        crypto_controller_fixture, "get_expiration", return_value="2025-12-31T23:59:59"
    )

    # Mock os.path.exists to return True for all key files
    with patch("os.path.exists", return_value=True):
        crypto_controller_fixture.get_status()
        logger.debug("Called get_status method.")
        captured = capsys.readouterr()
        logger.debug(f"Captured output: {captured.out}")
        assert "Certificate Vault Exists: Yes" in captured.out
        assert "Public Key Exists: Yes" in captured.out
        assert "Private Key Exists: Yes" in captured.out
        assert "Key Pair File Exists: Yes" in captured.out
        assert "Key Verification: Yes" in captured.out
        assert "Expiration: 2025-12-31T23:59:59" in captured.out
        logger.debug("Verified that get_status output is correct.")


def test_fetch_private_key_password(mock_requests_get, crypto_controller_fixture: CryptoController):
    """
    Test fetching the private key password from the module-level function.
    """
    logger.debug("Testing fetch_private_key_password function.")
    password = fetch_private_key_password()
    logger.debug(f"Fetched private key password: {password}")
    assert password == "secure_pass"
    mock_requests_get.assert_called_once_with(
        "https://api.mocked.com/get_password",
        headers={
            "content-type": "application/json",
            "token_security": "mocked_secure_token",
        },
        timeout=5,
    )
    logger.debug("Verified that fetch_private_key_password fetched the correct password.")


def test_send_expiration_alert(mock_smtp, crypto_controller_fixture: CryptoController):
    """
    Test sending an expiration alert email via the module-level function.
    """
    logger.debug("Testing send_expiration_alert function.")
    expiration_date = datetime.now() + timedelta(days=30)
    send_expiration_alert(expiration_date)
    logger.debug("Called send_expiration_alert method.")

    # Verify SMTP interactions
    mock_smtp.assert_called_with("smtp.mocked.com", 587)
    instance = mock_smtp.return_value.__enter__.return_value
    instance.starttls.assert_called_once()
    instance.login.assert_called_with("mocked_user@mocked.com", "mocked_password")
    instance.sendmail.assert_called_once()
    logger.debug("Verified that SMTP methods were called correctly.")


def test_renew_keys_confirm_yes(crypto_controller_fixture: CryptoController, mocker):
    """
    Test renewing keys when user confirms with 'yes'.
    """
    logger.debug("Testing renew_keys method with user confirmation 'yes'.")
    # Mock user input to return 'yes'
    mock_input = mocker.patch("crypto_controller.main.input", return_value="yes")
    # Mock clean_cert_vault and create_keys methods
    mock_clean = mocker.patch.object(crypto_controller_fixture, "clean_cert_vault")
    mock_create = mocker.patch.object(crypto_controller_fixture, "create_keys")

    crypto_controller_fixture.renew_keys()
    logger.debug("Called renew_keys method.")

    mock_clean.assert_called_once()
    mock_create.assert_called_once()
    logger.debug("Verified that clean_cert_vault and create_keys were called.")


def test_renew_keys_confirm_no(crypto_controller_fixture: CryptoController, mocker):
    """
    Test renewing keys when user declines with 'no'.
    """
    logger.debug("Testing renew_keys method with user confirmation 'no'.")
    # Mock user input to return 'no'
    mock_input = mocker.patch("crypto_controller.main.input", return_value="no")
    # Mock clean_cert_vault and create_keys methods
    mock_clean = mocker.patch.object(crypto_controller_fixture, "clean_cert_vault")
    mock_create = mocker.patch.object(crypto_controller_fixture, "create_keys")
    # Mock sys.exit
    mock_exit = mocker.patch("crypto_controller.main.sys.exit")

    crypto_controller_fixture.renew_keys()
    logger.debug("Called renew_keys method.")

    mock_clean.assert_not_called()
    mock_create.assert_not_called()
    mock_exit.assert_called_once_with(0)
    logger.debug(
        "Verified that clean_cert_vault and create_keys were not called and sys.exit was called with 0."
    )


def test_resolve_key_pair_name_finds_valid_range(tmp_path):
    """Finds existing .kp whose year range contains current year."""
    current_year = datetime.now().year
    kp_name = f"Crypto-Key-Pair-{current_year - 1}-{current_year + 5}.kp"
    (tmp_path / kp_name).write_text("dummy")
    result = _resolve_key_pair_name(str(tmp_path))
    assert result == kp_name[:-3]


def test_resolve_key_pair_name_no_certs_fallback(tmp_path):
    """Falls back to new range-based name when no valid .kp exists."""
    current_year = datetime.now().year
    result = _resolve_key_pair_name(str(tmp_path))
    assert result == f"Crypto-Key-Pair-{current_year}-{current_year + int(CERT_EXPIRATION_YEARS)}"


def test_resolve_key_pair_name_expired_range_ignored(tmp_path):
    """Ignores .kp file whose range has already expired."""
    (tmp_path / "Crypto-Key-Pair-2020-2021.kp").write_text("dummy")
    current_year = datetime.now().year
    result = _resolve_key_pair_name(str(tmp_path))
    assert result == f"Crypto-Key-Pair-{current_year}-{current_year + int(CERT_EXPIRATION_YEARS)}"


def test_resolve_key_pair_name_simulates_2027(tmp_path):
    """In 2027, finds Crypto-Key-Pair-2026-2032 since 2026 <= 2027 <= 2032."""
    (tmp_path / "Crypto-Key-Pair-2026-2032.kp").write_text("dummy")
    with patch("crypto_controller.main.datetime") as mock_dt:
        mock_dt.now.return_value = datetime(2027, 1, 1)
        result = _resolve_key_pair_name(str(tmp_path))
    assert result == "Crypto-Key-Pair-2026-2032"


def test_renew_keys_invalid_confirmation(crypto_controller_fixture: CryptoController, mocker):
    """
    Test renewing keys with invalid user input.
    """
    logger.debug("Testing renew_keys method with invalid user confirmation input.")
    # Mock user input to return 'invalid'
    mock_input = mocker.patch("crypto_controller.main.input", return_value="invalid")
    # Mock clean_cert_vault and create_keys methods
    mock_clean = mocker.patch.object(crypto_controller_fixture, "clean_cert_vault")
    mock_create = mocker.patch.object(crypto_controller_fixture, "create_keys")
    # Mock sys.exit
    mock_exit = mocker.patch("crypto_controller.main.sys.exit")

    crypto_controller_fixture.renew_keys()
    logger.debug("Called renew_keys method with invalid input.")

    mock_clean.assert_not_called()
    mock_create.assert_not_called()
    mock_exit.assert_called_once_with(1)
    logger.debug(
        "Verified that clean_cert_vault and create_keys were not called and sys.exit was called with 1."
    )


# Extended coverage: logger configuration, footprints, vault management,
# hybrid encryption error paths, verify branches and the CLI entry point.


def test_configure_logger_invalid_level_raises():
    """An unknown log level raises ValueError before touching any handler."""
    with pytest.raises(ValueError, match="Invalid log level"):
        configure_logger("WHISPER")


def test_configure_logger_sets_handlers(tmp_path, monkeypatch):
    """A valid level configures rotating file and console handlers."""
    monkeypatch.chdir(tmp_path)
    configure_logger("DEBUG")
    assert cc_main.logger.level == logging.DEBUG
    assert len(cc_main.logger.handlers) == 2


def _write_valid_pem(path: str, key_type: str) -> None:
    """Writes a PEM file whose body is valid base64 so footprints can be computed."""
    der_body = base64.encodebytes(b"dummy der payload for footprint tests")
    if key_type == "public":
        begin, end = b"-----BEGIN PUBLIC KEY-----\n", b"-----END PUBLIC KEY-----\n"
    else:
        begin, end = (
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
            b"-----END ENCRYPTED PRIVATE KEY-----\n",
        )
    with open(path, "wb") as pem_file:
        pem_file.write(begin + der_body + end)


def test_get_key_footprint_public_and_private(temp_cert_vault):
    """Footprints are generated for valid public and private PEM files."""
    public_path = os.path.join(temp_cert_vault, "key.pub")
    private_path = os.path.join(temp_cert_vault, "key.key")
    _write_valid_pem(public_path, "public")
    _write_valid_pem(private_path, "private")

    public_fp = get_key_footprint(public_path, "public")
    private_fp = get_key_footprint(private_path, "private")

    for footprint in (public_fp, private_fp):
        assert len(footprint.sha1) == 40
        assert len(footprint.sha256) == 64


def test_get_key_footprint_invalid_type_raises(temp_cert_vault):
    """An unknown key type raises ValueError."""
    path = os.path.join(temp_cert_vault, "key.pub")
    create_dummy_pem(path, "public")
    with pytest.raises(ValueError, match="Invalid key type"):
        get_key_footprint(path, "ssh")


def test_get_key_footprint_invalid_pem_raises(temp_cert_vault):
    """A file without PEM markers raises IOError."""
    path = os.path.join(temp_cert_vault, "not_a_key.txt")
    with open(path, "w") as plain_file:
        plain_file.write("plain text, no markers")
    with pytest.raises(IOError, match="Not a valid PEM file"):
        get_key_footprint(path, "public")


def test_check_cert_vault_exists(crypto_controller_fixture, temp_cert_vault):
    """The vault existence check reflects the filesystem state."""
    assert crypto_controller_fixture.check_cert_vault_exists() is True
    shutil.rmtree(temp_cert_vault)
    assert crypto_controller_fixture.check_cert_vault_exists() is False
    crypto_controller_fixture.create_cert_vault()  # restore for fixture teardown


def test_create_cert_vault_failure_raises(crypto_controller_fixture, mocker):
    """A filesystem error while creating the vault is re-raised."""
    mocker.patch("crypto_controller.main.os.makedirs", side_effect=PermissionError("denied"))
    with pytest.raises(PermissionError):
        crypto_controller_fixture.create_cert_vault()


def test_clean_cert_vault_recreates_empty_vault(crypto_controller_fixture, temp_cert_vault):
    """Cleaning removes vault contents and recreates the directory."""
    leftover = os.path.join(temp_cert_vault, "old.key")
    with open(leftover, "w") as old_file:
        old_file.write("old")
    crypto_controller_fixture.clean_cert_vault()
    assert os.path.exists(temp_cert_vault)
    assert os.listdir(temp_cert_vault) == []


def test_clean_cert_vault_failure_raises(crypto_controller_fixture, mocker):
    """A filesystem error while cleaning the vault is re-raised."""
    mocker.patch("crypto_controller.main.shutil.rmtree", side_effect=OSError("busy"))
    with pytest.raises(OSError):
        crypto_controller_fixture.clean_cert_vault()


def test_encrypt_hybrid_failure_raises(crypto_controller_fixture, mocker):
    """A key loading failure during encryption is re-raised."""
    mocker.patch.object(crypto_controller_fixture, "load_keys", side_effect=RuntimeError("no keys"))
    with pytest.raises(RuntimeError):
        crypto_controller_fixture.encrypt_hybrid("secret")


def test_decrypt_hybrid_bad_format_exits_1(crypto_controller_fixture, mocker):
    """Encrypted data without the three-part format exits with code 1."""
    mocker.patch.object(
        crypto_controller_fixture, "load_keys", return_value=(mock.Mock(), mock.Mock())
    )
    with pytest.raises(SystemExit) as exc_info:
        crypto_controller_fixture.decrypt_hybrid("not-three-parts")
    assert exc_info.value.code == 1


def test_decrypt_reraises_unexpected_errors(crypto_controller_fixture, mocker):
    """decrypt re-raises when decrypt_hybrid fails without exiting."""
    mocker.patch.object(crypto_controller_fixture, "decrypt_hybrid", side_effect=ValueError("boom"))
    with pytest.raises(ValueError):
        crypto_controller_fixture.decrypt("anything")


def _prepare_verify_data(controller, mocker, **overrides):
    """Writes a key pair file with identity-decrypted JSON data for verify tests."""
    create_dummy_pem(controller.public_key_file, "public")
    create_dummy_pem(controller.private_key_file, "private")
    key_pair_data = {
        "public_key_file": controller.public_key_file,
        "public_fp_sha1": "sha1",
        "public_fp_sha256": "sha256",
        "private_key_file": controller.private_key_file,
        "private_fp_sha1": "sha1",
        "private_fp_sha256": "sha256",
        "key_pair_file": controller.key_pair_file,
        "creation_date": datetime.now().strftime("%d%m%Y%H%M%S"),
        "expiration_date": (datetime.now() + timedelta(days=365)).strftime("%d%m%Y%H%M%S"),
    }
    key_pair_data.update(overrides)
    mocker.patch.object(controller, "decrypt", side_effect=lambda x: x)
    with open(controller.key_pair_file, "w") as kp_file:
        kp_file.write(json.dumps(key_pair_data))
    return key_pair_data


def test_verify_missing_public_key_file(crypto_controller_fixture, mocker):
    """verify fails when the referenced public key file does not exist."""
    _prepare_verify_data(
        crypto_controller_fixture,
        mocker,
        public_key_file=crypto_controller_fixture.public_key_file + ".missing",
    )
    assert crypto_controller_fixture.verify() is False


def test_verify_missing_private_key_file(crypto_controller_fixture, mocker):
    """verify fails when the referenced private key file does not exist."""
    _prepare_verify_data(
        crypto_controller_fixture,
        mocker,
        private_key_file=crypto_controller_fixture.private_key_file + ".missing",
    )
    assert crypto_controller_fixture.verify() is False


def test_verify_public_fingerprint_mismatch(crypto_controller_fixture, mocker):
    """verify fails when the public key fingerprints do not match."""
    _prepare_verify_data(crypto_controller_fixture, mocker)
    mocker.patch(
        "crypto_controller.main.get_key_footprint", return_value=Footprint("other", "other")
    )
    assert crypto_controller_fixture.verify() is False


def test_verify_private_fingerprint_mismatch(crypto_controller_fixture, mocker):
    """verify fails when the private key fingerprints do not match."""
    _prepare_verify_data(crypto_controller_fixture, mocker)
    mocker.patch(
        "crypto_controller.main.get_key_footprint",
        side_effect=[Footprint("sha1", "sha256"), Footprint("other", "other")],
    )
    assert crypto_controller_fixture.verify() is False


def test_verify_key_pair_path_mismatch(crypto_controller_fixture, mocker):
    """verify fails when the key pair file path differs from the expected one."""
    _prepare_verify_data(crypto_controller_fixture, mocker, key_pair_file="/elsewhere/kp.kp")
    mocker.patch(
        "crypto_controller.main.get_key_footprint", return_value=Footprint("sha1", "sha256")
    )
    assert crypto_controller_fixture.verify() is False


def test_verify_expired_key_pair(crypto_controller_fixture, mocker):
    """verify fails when the key pair expiration date is in the past."""
    _prepare_verify_data(
        crypto_controller_fixture,
        mocker,
        expiration_date=(datetime.now() - timedelta(days=1)).strftime("%d%m%Y%H%M%S"),
    )
    mocker.patch(
        "crypto_controller.main.get_key_footprint", return_value=Footprint("sha1", "sha256")
    )
    assert crypto_controller_fixture.verify() is False


def test_get_expiration_returns_iso_date(crypto_controller_fixture, mocker):
    """The expiration date is returned in ISO format."""
    with open(crypto_controller_fixture.key_pair_file, "w") as kp_file:
        kp_file.write("encrypted")
    mocker.patch.object(
        crypto_controller_fixture,
        "decrypt",
        return_value=json.dumps({"expiration_date": "31122026235959"}),
    )
    assert crypto_controller_fixture.get_expiration() == "2026-12-31T23:59:59"


def test_get_expiration_missing_field_returns_unknown(crypto_controller_fixture, mocker):
    """A key pair payload without expiration date returns 'Unknown'."""
    with open(crypto_controller_fixture.key_pair_file, "w") as kp_file:
        kp_file.write("encrypted")
    mocker.patch.object(crypto_controller_fixture, "decrypt", return_value="{}")
    assert crypto_controller_fixture.get_expiration() == "Unknown"


def test_get_expiration_failure_returns_unknown(crypto_controller_fixture):
    """A missing key pair file returns 'Unknown'."""
    assert crypto_controller_fixture.get_expiration() == "Unknown"


def test_create_keys_skips_when_verification_passes(crypto_controller_fixture, mocker):
    """create_keys is a no-op when the existing keys verify correctly."""
    mocker.patch.object(crypto_controller_fixture, "verify", return_value=True)
    mock_generate = mocker.patch("crypto_controller.main.rsa.generate_private_key")
    crypto_controller_fixture.create_keys()
    mock_generate.assert_not_called()


def test_create_keys_failure_raises(crypto_controller_fixture, mocker):
    """A key generation failure is re-raised."""
    mocker.patch.object(crypto_controller_fixture, "verify", return_value=False)
    mocker.patch(
        "crypto_controller.main.rsa.generate_private_key", side_effect=RuntimeError("rsa boom")
    )
    with pytest.raises(RuntimeError):
        crypto_controller_fixture.create_keys()


def test_renew_keys_failure_exits_1(crypto_controller_fixture, mocker):
    """A failure while renewing keys exits with code 1."""
    mocker.patch("crypto_controller.main.input", return_value="yes")
    mocker.patch.object(
        crypto_controller_fixture, "clean_cert_vault", side_effect=RuntimeError("disk")
    )
    with pytest.raises(SystemExit) as exc_info:
        crypto_controller_fixture.renew_keys()
    assert exc_info.value.code == 1


def test_load_keys_auto_creates_missing_keys(crypto_controller_fixture):
    """load_keys regenerates real key material when the vault is empty."""
    public_key, private_key = crypto_controller_fixture.load_keys()
    assert public_key is not None
    assert private_key is not None
    # A second call now loads the freshly created keys directly
    public_key_again, private_key_again = crypto_controller_fixture.load_keys()
    assert public_key_again is not None
    assert private_key_again is not None


def test_get_status_failure_prints_fallback(crypto_controller_fixture, mocker, capsys):
    """A status failure prints the fallback message instead of raising."""
    mocker.patch.object(
        crypto_controller_fixture, "check_cert_vault_exists", side_effect=RuntimeError("boom")
    )
    crypto_controller_fixture.get_status()
    assert "Failed to retrieve status" in capsys.readouterr().out


def test_parse_arguments_defaults(monkeypatch):
    """parse_arguments resolves defaults for vault location and key pair name."""
    monkeypatch.setattr(sys, "argv", ["crypto_controller", "status"])
    args = parse_arguments()
    assert args.operation == "status"
    assert args.value is None
    assert args.cert_location.endswith("certs")
    assert args.key_pair_name.startswith("Crypto-Key-Pair-")
    assert args.log_level == "INFO"


def test_parse_arguments_custom_values(monkeypatch):
    """parse_arguments honors explicit values for every option."""
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "crypto_controller",
            "encrypt",
            "secret",
            "--cert-location",
            "/x",
            "--key-pair-name",
            "kp",
            "--log-level",
            "DEBUG",
        ],
    )
    args = parse_arguments()
    assert args.operation == "encrypt"
    assert args.value == "secret"
    assert args.cert_location == "/x"
    assert args.key_pair_name == "kp"
    assert args.log_level == "DEBUG"


def test_parse_arguments_invalid_operation_exits_2(monkeypatch):
    """An unknown operation makes argparse exit with code 2."""
    monkeypatch.setattr(sys, "argv", ["crypto_controller", "explode"])
    with pytest.raises(SystemExit) as exc_info:
        parse_arguments()
    assert exc_info.value.code == 2


def test_fetch_private_key_password_falls_back_to_env(mocker, monkeypatch):
    """API failures fall back to the KP_PASSWORD environment variable."""
    mocker.patch(
        "crypto_controller.main.requests.get",
        side_effect=requests.exceptions.RequestException("api down"),
    )
    monkeypatch.setenv("KP_PASSWORD", "env_pass")
    assert fetch_private_key_password() == "env_pass"


def test_send_expiration_alert_incomplete_config_skips_send(mock_smtp, monkeypatch):
    """Without full SMTP configuration no email is attempted."""
    monkeypatch.delenv("SMTP_SERVER")
    send_expiration_alert(datetime.now() + timedelta(days=5))
    mock_smtp.assert_not_called()


def test_send_expiration_alert_smtp_failure_does_not_raise(mock_smtp):
    """SMTP failures are logged without raising."""
    mock_smtp.side_effect = RuntimeError("smtp down")
    send_expiration_alert(datetime.now() + timedelta(days=5))


# CLI main() coverage


@pytest.fixture
def cli_controller(tmp_path, monkeypatch, mocker):
    """Mocks the controller and password fetch for CLI main() tests."""
    monkeypatch.chdir(tmp_path)
    mocker.patch("crypto_controller.main.fetch_private_key_password", return_value="pwd")
    mock_controller = mock.Mock()
    mocker.patch("crypto_controller.main.CryptoController", return_value=mock_controller)
    return mock_controller


def _run_cli(monkeypatch, *argv):
    """Runs the module CLI with the given arguments."""
    monkeypatch.setattr(sys, "argv", ["crypto_controller", *argv])
    cc_main.main()


def test_main_init_with_existing_vault(cli_controller, monkeypatch):
    """init with an existing vault only creates new keys."""
    cli_controller.check_cert_vault_exists.return_value = True
    _run_cli(monkeypatch, "init")
    cli_controller.create_keys.assert_called_once()
    cli_controller.create_cert_vault.assert_not_called()


def test_main_init_creates_vault(cli_controller, monkeypatch):
    """init without a vault creates the vault and the keys."""
    cli_controller.check_cert_vault_exists.return_value = False
    _run_cli(monkeypatch, "init")
    cli_controller.create_cert_vault.assert_called_once()
    cli_controller.create_keys.assert_called_once()


def test_main_renew_with_existing_vault(cli_controller, monkeypatch):
    """renew with an existing vault delegates to renew_keys."""
    cli_controller.check_cert_vault_exists.return_value = True
    _run_cli(monkeypatch, "renew")
    cli_controller.renew_keys.assert_called_once()


def test_main_renew_without_vault_creates_keys(cli_controller, monkeypatch):
    """renew without a vault creates the vault and the keys."""
    cli_controller.check_cert_vault_exists.return_value = False
    _run_cli(monkeypatch, "renew")
    cli_controller.create_cert_vault.assert_called_once()
    cli_controller.create_keys.assert_called_once()


def test_main_encrypt_without_value_exits_1(cli_controller, monkeypatch):
    """encrypt without a value exits with code 1."""
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(monkeypatch, "encrypt")
    assert exc_info.value.code == 1


def test_main_encrypt_prints_result(cli_controller, monkeypatch, capsys):
    """encrypt prints the encrypted value when verification passes."""
    cli_controller.verify.return_value = True
    cli_controller.encrypt.return_value = "ENCRYPTED"
    _run_cli(monkeypatch, "encrypt", "secret")
    assert "ENCRYPTED" in capsys.readouterr().out


def test_main_encrypt_with_failed_verification_exits_1(cli_controller, monkeypatch):
    """encrypt aborts with code 1 when verification fails."""
    cli_controller.verify.return_value = False
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(monkeypatch, "encrypt", "secret")
    assert exc_info.value.code == 1


def test_main_decrypt_without_value_exits_1(cli_controller, monkeypatch):
    """decrypt without a value exits with code 1."""
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(monkeypatch, "decrypt")
    assert exc_info.value.code == 1


def test_main_decrypt_prints_result(cli_controller, monkeypatch, capsys):
    """decrypt prints the plain value when verification passes."""
    cli_controller.verify.return_value = True
    cli_controller.decrypt.return_value = "PLAIN"
    _run_cli(monkeypatch, "decrypt", "payload")
    assert "PLAIN" in capsys.readouterr().out


def test_main_decrypt_with_failed_verification_exits_1(cli_controller, monkeypatch):
    """decrypt aborts with code 1 when verification fails."""
    cli_controller.verify.return_value = False
    with pytest.raises(SystemExit) as exc_info:
        _run_cli(monkeypatch, "decrypt", "payload")
    assert exc_info.value.code == 1


def test_main_status_invokes_get_status(cli_controller, monkeypatch):
    """status delegates to get_status."""
    _run_cli(monkeypatch, "status")
    cli_controller.get_status.assert_called_once()


def test_main_operation_errors_are_logged_not_raised(cli_controller, monkeypatch, caplog):
    """Operation failures are logged and main() returns normally."""
    cli_controller.check_cert_vault_exists.side_effect = RuntimeError("boom")
    with caplog.at_level(logging.ERROR, logger="__main__"):
        _run_cli(monkeypatch, "init")
    assert "Operation 'init' failed" in caplog.text
