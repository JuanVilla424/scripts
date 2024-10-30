import os
import sys
import argparse
import logging
from logging.handlers import RotatingFileHandler
import shutil
import hashlib
import base64
from collections import namedtuple
from datetime import datetime, timedelta
import requests
import warnings
import smtplib
from email.mime.text import MIMEText
import json  # Added import for JSON handling

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from dotenv import load_dotenv

# Suppress warnings
warnings.filterwarnings("ignore")

# Load environment variables from .env file
load_dotenv()

CERT_EXPIRATION_YEARS = os.getenv("CERT_EXPIRATION_YEARS", "1")

# Verify that required environment variables are set
REQUIRED_ENV_VARS = [CERT_EXPIRATION_YEARS]

if not all(REQUIRED_ENV_VARS):
    raise EnvironmentError("One or more required environment variables are missing.")

# Configure logger
logger = logging.getLogger("__main__")


def configure_logger(log_level: str = "INFO") -> None:
    """
    Configures the logger with rotating file handler and console handler.

    Args:
        log_level (str): Logging level (INFO, DEBUG, etc.).
    """
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    logger.setLevel(numeric_level)

    # File handler with rotation
    file_handler = RotatingFileHandler(
        "crypto_controller.log", maxBytes=5 * 1024 * 1024, backupCount=5
    )
    # Console handler
    console_handler = logging.StreamHandler()

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


# Structure to store footprints
Footprint = namedtuple("Footprint", ["sha1", "sha256"])


def get_key_footprint(key_file_path: str, key_type: str) -> Footprint:
    """
    Generates SHA1 and SHA256 footprints for a given key file.

    Args:
        key_file_path (str): Path to the key file.
        key_type (str): Type of the key ('public' or 'private').

    Returns:
        Footprint: Namedtuple containing SHA1 and SHA256 hashes.
    """
    try:
        with open(key_file_path, "rb") as pem_file:
            pem_data = pem_file.read()

        if key_type == "public":
            marker_begin = b"-----BEGIN PUBLIC KEY-----"
            marker_end = b"-----END PUBLIC KEY-----"
        elif key_type == "private":
            marker_begin = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
            marker_end = b"-----END ENCRYPTED PRIVATE KEY-----"
        else:
            raise ValueError("Invalid key type specified.")

        start = pem_data.find(marker_begin)
        end = pem_data.find(marker_end, start)
        if start == -1 or end == -1:
            raise IOError("Not a valid PEM file.")

        key_body = pem_data[start + len(marker_begin) : end]
        der = base64.decodebytes(key_body.replace(b"\n", b""))

        sha1 = hashlib.sha1(der).hexdigest()
        sha256 = hashlib.sha256(der).hexdigest()
        logger.debug(f"Generated footprint for {key_type} key: SHA1={sha1}, SHA256={sha256}")
        return Footprint(sha1, sha256)
    except Exception as error:
        logger.error(f"Error generating footprint for {key_type} key: {error}", exc_info=True)
        raise


class CryptoController:
    """Crypto Controller for encryption and decryption operations."""

    def __init__(self, cert_location: str, key_pair_name: str, private_key_pass: str):
        """
        Initializes the CryptoController.

        Args:
            cert_location (str): Path to the certificate vault.
            key_pair_name (str): Name of the key pair.
            private_key_pass (str): Password for the private key.
        """
        self.cert_location = cert_location
        self.key_pair_name = key_pair_name
        self.private_key_pass = private_key_pass.encode("utf-8")

        self.public_key_file = os.path.join(cert_location, f"{self.key_pair_name}.pub")
        self.private_key_file = os.path.join(cert_location, f"{self.key_pair_name}.key")
        self.key_pair_file = os.path.join(cert_location, f"{self.key_pair_name}.kp")

    def check_cert_vault_exists(self) -> bool:
        """
        Checks if the certificate vault exists.

        Returns:
            bool: True if exists, False otherwise.
        """
        exists = os.path.exists(self.cert_location)
        logger.debug(f"Certificate vault exists: {exists}")
        return exists

    def create_cert_vault(self) -> None:
        """
        Creates the certificate vault directory.
        """
        try:
            os.makedirs(self.cert_location, mode=0o700, exist_ok=True)
            logger.info(f"Created certificate vault at {self.cert_location}")
        except Exception as error:
            logger.error(f"Can't create certificate vault: {error}", exc_info=True)
            raise

    def clean_cert_vault(self) -> None:
        """
        Cleans the certificate vault by removing all contents.
        """
        try:
            shutil.rmtree(self.cert_location)
            logger.info(f"Cleaned certificate vault at {self.cert_location}")
            self.create_cert_vault()
        except Exception as error:
            logger.error(f"Failed to clean certificate vault: {error}", exc_info=True)
            raise

    def encrypt_hybrid(self, plain_text: str) -> str:
        """
        Encrypts plain text using hybrid encryption (AES + RSA).

        Args:
            plain_text (str): The text to encrypt.

        Returns:
            str: Encrypted data as a concatenated Base64 string (encrypted_aes_key:iv:ciphertext).
        """
        try:
            public_key, _ = self.load_keys()

            # Generate a random AES key and IV
            aes_key = os.urandom(32)  # AES-256
            iv = os.urandom(16)  # 128-bit IV

            # Encrypt the plain text with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plain_text.encode("utf-8")) + encryptor.finalize()

            # Encrypt the AES key with the RSA public key
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Encode all parts with Base64
            encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode("utf-8")
            iv_b64 = base64.b64encode(iv).decode("utf-8")
            ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")

            # Concatenate with colon as delimiter
            encrypted_data = f"{encrypted_aes_key_b64}:{iv_b64}:{ciphertext_b64}"
            logger.debug("Hybrid encryption successful.")
            return encrypted_data

        except Exception as error:
            logger.error(f"Hybrid encryption failed: {error}", exc_info=True)
            raise

    def decrypt_hybrid(self, encrypted_data: str) -> str:
        """
        Decrypts data encrypted with hybrid encryption (AES + RSA).

        Args:
            encrypted_data (str): The encrypted data as a concatenated Base64 string (encrypted_aes_key:iv:ciphertext).

        Returns:
            str: Decrypted plain text.
        """
        try:
            _, private_key = self.load_keys()

            # Split the encrypted data
            parts = encrypted_data.split(":")
            if len(parts) != 3:
                raise ValueError(
                    "Encrypted data is not in the correct format (expected 3 parts separated by ':')."
                )

            encrypted_aes_key_b64, iv_b64, ciphertext_b64 = parts

            # Decode from Base64
            encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
            iv = base64.b64decode(iv_b64)
            ciphertext = base64.b64decode(ciphertext_b64)

            # Decrypt the AES key with RSA private key
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Decrypt the ciphertext with AES key
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()

            decrypted_str = decrypted_text.decode("utf-8")
            logger.debug("Hybrid decryption successful.")
            return decrypted_str

        except Exception as error:
            logger.error(f"Hybrid decryption failed: {error}", exc_info=True)
            logger.fatal("Can't decrypt encrypted data.")
            sys.exit(1)

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts plain text using hybrid encryption.

        Args:
            plain_text (str): The text to encrypt.

        Returns:
            str: Encrypted data as a concatenated Base64 string.
        """
        return self.encrypt_hybrid(plain_text)

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypts encrypted text using hybrid encryption.

        Args:
            encrypted_text (str): The text to decrypt (concatenated Base64 string).

        Returns:
            str: Decrypted plain text.
        """
        try:
            decrypted = self.decrypt_hybrid(encrypted_text)
            return decrypted
        except Exception as error:
            logger.error(f"Decryption failed: {error}", exc_info=True)
            raise

    def verify(self) -> bool:
        """
        Verifies the integrity and validity of the keys.

        Returns:
            bool: True if verification is successful, False otherwise.
        """
        try:
            with open(self.key_pair_file, "r") as kp_file:
                encrypted_kp = kp_file.read()
            decrypted_kp = self.decrypt(encrypted_kp)
            kp_data = json.loads(decrypted_kp)

            # Required fields in kp_data
            required_fields = {
                "public_key_file",
                "public_fp_sha1",
                "public_fp_sha256",
                "private_key_file",
                "private_fp_sha1",
                "private_fp_sha256",
                "key_pair_file",
                "creation_date",
                "expiration_date",
            }

            missing_fields = required_fields - kp_data.keys()
            if missing_fields:
                logger.error(f"Missing fields in key pair data: {missing_fields}")
                return False

            # Check if key files exist
            if not os.path.exists(kp_data["public_key_file"]):
                logger.error(f"Public key file does not exist: {kp_data['public_key_file']}")
                return False

            if not os.path.exists(kp_data["private_key_file"]):
                logger.error(f"Private key file does not exist: {kp_data['private_key_file']}")
                return False

            # Verify public key footprint
            current_public_fp = get_key_footprint(kp_data["public_key_file"], "public")
            if (
                current_public_fp.sha1 != kp_data["public_fp_sha1"]
                or current_public_fp.sha256 != kp_data["public_fp_sha256"]
            ):
                logger.error("Public key fingerprints do not match.")
                return False

            # Verify private key footprint
            current_private_fp = get_key_footprint(kp_data["private_key_file"], "private")
            if (
                current_private_fp.sha1 != kp_data["private_fp_sha1"]
                or current_private_fp.sha256 != kp_data["private_fp_sha256"]
            ):
                logger.error("Private key fingerprints do not match.")
                return False

            # Optionally, check if the key pair file path matches
            if kp_data["key_pair_file"] != self.key_pair_file:
                logger.error("Key pair file path does not match the expected location.")
                return False

            # Optionally, check if the current date is before expiration
            expiration_date = datetime.strptime(kp_data["expiration_date"], "%d%m%Y%H%M%S")
            if datetime.now() > expiration_date:
                logger.error("The key pair has expired.")
                return False

            logger.debug("Key verification successful.")
            return True
        except Exception as error:
            logger.error(f"Verification failed: {error}", exc_info=True)
            return False

    def get_expiration(self) -> str:
        """
        Retrieves the expiration date of the key pair.

        Returns:
            str: Expiration date in ISO format, or 'Unknown' if not available.
        """
        try:
            with open(self.key_pair_file, "r") as kp_file:
                encrypted_kp = kp_file.read()
            decrypted_kp = self.decrypt(encrypted_kp)
            logger.debug(f"Decrypted key pair content: {decrypted_kp}")

            # Parse JSON
            kp_data = json.loads(decrypted_kp)
            logger.debug(f"Key pair data: {kp_data}")

            expiration_str = kp_data.get("expiration_date")
            if not expiration_str:
                raise ValueError("Expiration date not found in key pair data.")

            # Parse the date string
            expiration_date = datetime.strptime(expiration_str, "%d%m%Y%H%M%S")
            # Return the date in ISO format
            logger.debug(f"Expiration date retrieved successfully: {expiration_date.isoformat()}")
            return expiration_date.isoformat()
        except Exception as error:
            logger.error(f"Failed to get expiration date: {error}", exc_info=True)
            return "Unknown"

    def create_keys(self) -> None:
        """
        Generates a new RSA key pair and stores them securely.
        """
        if self.verify():
            logger.info("Keys validation successful, nothing to do.")
            return
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096, backend=default_backend()
            )
            # Crucial: Do NOT log private and public keys
            encrypted_private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(self.private_key_pass),
            )
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            with open(self.private_key_file, "wb+") as priv_file:
                priv_file.write(encrypted_private_key)
            with open(self.public_key_file, "wb+") as pub_file:
                pub_file.write(public_key)

            logger.info("Keys generated successfully.")

            # Generate footprints
            public_fp = get_key_footprint(self.public_key_file, "public")
            private_fp = get_key_footprint(self.private_key_file, "private")

            # Create key pair content as JSON
            now = datetime.now()
            expire = now + timedelta(days=365 * int(CERT_EXPIRATION_YEARS))
            key_pair_data = {
                "public_key_file": self.public_key_file,
                "public_fp_sha1": public_fp.sha1,
                "public_fp_sha256": public_fp.sha256,
                "private_key_file": self.private_key_file,
                "private_fp_sha1": private_fp.sha1,
                "private_fp_sha256": private_fp.sha256,
                "key_pair_file": self.key_pair_file,
                "creation_date": now.strftime("%d%m%Y%H%M%S"),
                "expiration_date": expire.strftime("%d%m%Y%H%M%S"),
            }

            key_pair_content = json.dumps(key_pair_data)
            encrypted_kp = self.encrypt(key_pair_content)  # Uses hybrid encryption

            with open(self.key_pair_file, "w") as kp_file:
                kp_file.write(encrypted_kp)

            logger.info("Key pair file created and encrypted successfully.")

        except Exception as error:
            logger.error(f"Key creation failed: {error}", exc_info=True)
            raise

    def renew_keys(self) -> None:
        """
        Renews the existing keys by cleaning the vault and generating new keys.
        """
        try:
            confirmation = (
                input("Are you sure you want to renew the keys? Type yes/no: ").strip().lower()
            )
            if confirmation in ["yes", "y", "s", "si"]:
                self.clean_cert_vault()
                self.create_keys()
                logger.info("Keys renewed successfully.")
            elif confirmation in ["no", "n"]:
                logger.info("Key renewal cancelled by user.")
                sys.exit(0)
            else:
                logger.error("Invalid input for key renewal confirmation.")
                sys.exit(1)
        except Exception as error:
            logger.error(f"Key renewal failed: {error}", exc_info=True)
            sys.exit(1)

    def load_keys(self):
        """
        Loads the public and private keys from the certificate vault.

        Returns:
            tuple: Public key and private key objects.
        """
        try:
            with open(self.private_key_file, "rb") as priv_file:
                private_key = serialization.load_pem_private_key(
                    priv_file.read(), password=self.private_key_pass, backend=default_backend()
                )
            with open(self.public_key_file, "rb") as pub_file:
                public_key = serialization.load_pem_public_key(
                    pub_file.read(), backend=default_backend()
                )
            logger.debug("Keys loaded successfully.")
            return public_key, private_key
        except Exception as error:
            logger.error(f"Loading keys failed: {error}", exc_info=True)
            self.create_keys()
            with open(self.private_key_file, "rb") as priv_file:
                private_key = serialization.load_pem_private_key(
                    priv_file.read(), password=self.private_key_pass, backend=default_backend()
                )
            with open(self.public_key_file, "rb") as pub_file:
                public_key = serialization.load_pem_public_key(
                    pub_file.read(), backend=default_backend()
                )
            return public_key, private_key

    def get_status(self) -> None:
        """
        Retrieves and prints the status of the CryptoController.
        """
        try:
            status = {
                "Certificate Vault Exists": self.check_cert_vault_exists(),
                "Public Key Exists": os.path.exists(self.public_key_file),
                "Private Key Exists": os.path.exists(self.private_key_file),
                "Key Pair File Exists": os.path.exists(self.key_pair_file),
                "Key Verification": self.verify(),
                "Expiration": self.get_expiration(),
            }
            print("CryptoController Status:")
            for key, value in status.items():
                if isinstance(value, bool):
                    print(f" - {key}: {'Yes' if value else 'No'}")
                else:
                    print(f" - {key}: {value}")
        except Exception as error:
            logger.error(f"Failed to retrieve status: {error}", exc_info=True)
            print("Failed to retrieve status. Check logs for more details.")


def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Cryptography Controller for Encrypting and Decrypting Texts."
    )
    parser.add_argument(
        "operation",
        choices=["init", "renew", "encrypt", "decrypt", "status"],
        help="Operation to perform: init, renew, encrypt, decrypt, status.",
    )
    parser.add_argument(
        "value", nargs="?", help="Value to encrypt or decrypt (required for encrypt and decrypt)."
    )
    parser.add_argument(
        "--cert-location",
        default=os.path.join(os.getcwd(), "certs"),
        help="Location of the certificates. Defaults to 'certs' in the current directory.",
    )
    parser.add_argument(
        "--key-pair-name",
        default=f"Crypto-Key-Pair-{datetime.now().year}",
        help="Name of the key pair. Defaults to 'Crypto-Key-Pair-<YEAR>'.",
    )
    parser.add_argument(
        "--log-level",
        choices=["INFO", "DEBUG"],
        default="INFO",
        help="Logging level. Defaults to INFO.",
    )
    return parser.parse_args()


def fetch_private_key_password() -> str:
    """
    Fetches the private key password from a secure API endpoint.

    Returns:
        str: The private key password.
    """
    try:
        token_security = os.getenv("API_TOKEN_SECURITY")
        headers = {
            "content-type": "application/json",
            "token_security": token_security,
        }
        response = requests.get(
            os.getenv("API_URI"),
            headers=headers,
            timeout=int(os.getenv("API_TIMEOUT")),
        )
        response.raise_for_status()  # Raises HTTPError for bad responses
        pk_key_pass = response.json().get("value")
        return pk_key_pass
    except requests.exceptions.RequestException as e_requests_exception_fetch_password:
        logger.error(
            f"Error fetching private key password from api: {e_requests_exception_fetch_password}",
            exc_info=True,
        )
        try:
            logger.debug("Trying using KP_PASSWORD value...")
            pk_key_pass = os.getenv("KP_PASSWORD")
            return pk_key_pass
        except KeyError as e_key_error_fetch_password:
            logger.error(
                f"The key was not found in the environment: {e_key_error_fetch_password}",
                exc_info=True,
            )
            logger.error(
                "STARTING USING DEFAULT PASSWORD WHICH IS NOT RECOMMENDED, CLEAN AND SET THIS ONE TO .env FILE AS KP_PASSWORD..."
            )
            return "password123456789099ab5e7b9add0dc4e5"


def send_expiration_alert(expiration_date: datetime) -> None:
    """
    Sends an email alert about the impending expiration of keys.

    Args:
        expiration_date (datetime): The expiration date of the keys.
    """
    try:
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port = os.getenv("SMTP_PORT")
        smtp_user = os.getenv("SMTP_USER")
        smtp_password = os.getenv("SMTP_PASSWORD")
        recipient = os.getenv("ALERT_RECIPIENT")

        if not all([smtp_server, smtp_port, smtp_user, smtp_password, recipient]):
            logger.error("SMTP configuration is incomplete. Cannot send alert.")
            return

        subject = "CryptoController Keys Expiration Alert"
        body = f"The cryptographic keys are set to expire on {expiration_date.strftime('%Y-%m-%d %H:%M:%S')}. Please initiate the renewal process."

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_user
        msg["To"] = recipient

        with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, [recipient], msg.as_string())

        logger.info(f"Expiration alert sent to {recipient}.")
    except Exception as error:
        logger.error(f"Failed to send expiration alert: {error}", exc_info=True)


def main():
    """
    Main function to execute the Crypto Controller operations.
    """
    args = parse_arguments()
    configure_logger(args.log_level)

    # Fetch the private key password from the secure API
    private_key_pass = fetch_private_key_password()
    # Alternatively, if you prefer using environment variables, comment the above line and uncomment the following:
    # private_key_pass = os.getenv("PRIVATE_KEY_PASS")
    # if not private_key_pass:
    #     logger.error("Environment variable PRIVATE_KEY_PASS is not set.")
    #     sys.exit(1)

    crypto = CryptoController(
        cert_location=args.cert_location,
        key_pair_name=args.key_pair_name,
        private_key_pass=private_key_pass,
    )

    try:
        operation = args.operation.lower()
        if operation == "init":
            if crypto.check_cert_vault_exists():
                logger.info("Certificate vault already exists. Creating new keys.")
                crypto.create_keys()
            else:
                crypto.create_cert_vault()
                crypto.create_keys()

        elif operation == "renew":
            if crypto.check_cert_vault_exists():
                crypto.renew_keys()
            else:
                logger.info("Certificate vault does not exist. Creating vault and generating keys.")
                crypto.create_cert_vault()
                crypto.create_keys()

        elif operation == "encrypt":
            if not args.value:
                logger.error("Value to encrypt was not provided.")
                sys.exit(1)
            if crypto.verify():
                encrypted = crypto.encrypt(args.value)
                print(encrypted)
            else:
                logger.error("Key verification failed. Cannot encrypt.")
                sys.exit(1)

        elif operation == "decrypt":
            if not args.value:
                logger.error("Value to decrypt was not provided.")
                sys.exit(1)
            if crypto.verify():
                decrypted = crypto.decrypt(args.value)
                print(decrypted)
            else:
                logger.error("Key verification failed. Cannot decrypt.")
                sys.exit(1)

        elif operation == "status":
            crypto.get_status()

    except Exception as error:
        logger.error(f"Operation '{args.operation}' failed: {error}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
