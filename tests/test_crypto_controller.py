# tests/test_crypto_controller.py

import os
import json
from unittest import mock

import pytest
import shutil
import tempfile
import logging
from logging.handlers import RotatingFileHandler
from unittest.mock import patch, mock_open
from datetime import datetime, timedelta

# Import CryptoController and related functions from main.py
from crypto_controller.main import CryptoController, get_key_footprint, Footprint


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
    Test that environment variables are loaded correctly using load_dotenv.
    """
    logger.debug("Testing environment variable loading.")
    mock_load_dotenv.assert_called_once()
    assert crypto_controller_fixture.cert_location is not None
    assert crypto_controller_fixture.key_pair_name == "test_key_pair"
    logger.debug("Environment variables loaded and CryptoController initialized correctly.")


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

    # Mock the encrypt method to return JSON string
    mocker.patch.object(
        crypto_controller_fixture, "encrypt", return_value=json.dumps(key_pair_data)
    )
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

    # Mock the encrypt method to return JSON string
    mocker.patch.object(
        crypto_controller_fixture, "encrypt", return_value=json.dumps(key_pair_data)
    )

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
        assert "Key Verification: True" in captured.out
        assert "Expiration: 2025-12-31T23:59:59" in captured.out
        logger.debug("Verified that get_status output is correct.")


def test_fetch_private_key_password(mock_requests_get, crypto_controller_fixture: CryptoController):
    """
    Test fetching the private key password from a secure API endpoint.
    """
    logger.debug("Testing fetch_private_key_password method.")
    password = crypto_controller_fixture.fetch_private_key_password()
    logger.debug(f"Fetched private key password: {password}")
    assert password == "secure_pass"
    mock_requests_get.assert_called_once_with(
        "https://api.mocked.com/get_password",
        headers={
            "content-type": "application/json",
            "token_security": "mocked_secure_token",
        },
        timeout=5,  # Changed from "5" to 5 (integer)
    )
    logger.debug("Verified that fetch_private_key_password fetched the correct password.")


def test_send_expiration_alert(mock_smtp, crypto_controller_fixture: CryptoController):
    """
    Test sending an expiration alert email.
    """
    logger.debug("Testing send_expiration_alert method.")
    expiration_date = datetime.now() + timedelta(days=30)
    crypto_controller_fixture.send_expiration_alert(expiration_date)
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
