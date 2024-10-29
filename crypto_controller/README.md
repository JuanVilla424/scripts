# 🔐 CryptoController

![Status](https://img.shields.io/badge/Status-Stable-green.svg)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)
![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)

CryptoController is a robust Python application designed for secure key management, encryption, and decryption operations. It leverages hybrid encryption (AES + RSA) to ensure data confidentiality and integrity, making it ideal for applications requiring strong cryptographic safeguards.

## 📚 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Usage](#-usage)
  - [Initialization](#-initialization)
  - [Renewing Keys](#-renewing-keys)
  - [Encrypting Data](#-encrypting-data)
  - [Decrypting Data](#-decrypting-data)
  - [Checking Status](#-checking-status)
- [Environment Variables](#-environment-variables)
- [Logging](#-logging)
- [License](#-license)
- [Contact](#-contact)

## ✨ Features

- **Hybrid Encryption:** Combines AES (symmetric) and RSA (asymmetric) encryption for enhanced security.
- **Key Management:** Generates, verifies, and renews RSA key pairs securely.
- **Expiration Handling:** Tracks key expiration dates and sends email alerts before keys expire.
- **Status Reporting:** Provides detailed status reports of the cryptographic setup.
- **Secure Storage:** Stores keys in a protected certificate vault with appropriate permissions.
- **Logging:** Comprehensive logging with rotating file handlers for easy monitoring and debugging.

## 🛠️ Installation

1. **Clone the Repository:**

   ```bash
   cd crypto_controller
   ```

2. **Create a Virtual Environment**

   ```bash
   python -m venv venv
   ```

3. **Activate the Virtual Environment**

   On Unix or MacOS:

   ```bash
   source venv/bin/activate
   ```

   On Windows:

   ```bash
    .\venv\Scripts\activate
   ```

   - or

   ```bash
    powershell.exe -ExecutionPolicy Bypass -File .\venv\Scripts\Activate.ps1
   ```

4. **Upgrade pip**

   ```bash
   pip install --upgrade pip
   ```

5. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

   - Deactivate the Virtual Environment

   When you're done, deactivate the environment:

   ```bash
    deactivate
   ```

## ⚙️ Configuration

**Environment Variables**:

Create a .env file in the project root directory and populate it with the following variables:

```bash
CPU_USAGE_THRESHOLD=70.0
MEMORY_USAGE_THRESHOLD=395.0
DISK_SPACE_THRESHOLD=75.0
EXPIRATION=1
TOKEN_SECURITY=your_secure_token_here
SMTP_SERVER=smtp.example.com
SMTP_PORT=587
SMTP_USER=your_email@example.com
SMTP_PASSWORD=your_email_password
ALERT_RECIPIENT=recipient@example.com
```

- Descriptions:
  - CPU_USAGE_THRESHOLD: CPU usage percentage threshold.
  - MEMORY_USAGE_THRESHOLD: Memory usage threshold in MB.
  - DISK_SPACE_THRESHOLD: Disk space usage percentage threshold.
  - EXPIRATION: Number of years before key expiration.
  - TOKEN_SECURITY: Token for fetching the private key password securely.
  - SMTP_SERVER: SMTP server address for sending emails.
  - SMTP_PORT: SMTP server port.
  - SMTP_USER: SMTP server username.
  - SMTP_PASSWORD: SMTP server password.
  - ALERT_RECIPIENT: Email address to receive expiration alerts.

## 🚀 Usage

CryptoController supports several operations: init, renew, encrypt, decrypt, and status.

### 📦 Initialization

Generates a new RSA key pair and sets up the certificate vault.

```bash
python main.py init --log-level DEBUG
```

    Options:
        --cert-location: Directory to store certificates (default: certs in the current directory).
        --key-pair-name: Name of the key pair (default: Crypto-Key-Pair-<YEAR>).
        --log-level: Logging level (INFO or DEBUG).

### 🔄 Renewing Keys

Renews existing keys by cleaning the vault and generating new keys.

```bash
python main.py renew --log-level DEBUG
```

### 🔒 Encrypting Data

Encrypts plain text using hybrid encryption.

```bash
python main.py encrypt "Your sensitive data here" --log-level DEBUG
```

    Output: Encrypted Base64 string.

### 🔓 Decrypting Data

Decrypts previously encrypted data.

```bash
python main.py decrypt "EncryptedBase64StringHere" --log-level DEBUG
```

    Output: Decrypted plain text.

### 📝 Checking Status

Retrieves and displays the current status of the CryptoController.

```bash
python main.py status --log-level DEBUG
```

### 📜 Environment Variables

Ensure all required environment variables are set in the .env file:

    Resource Thresholds:
        CPU_USAGE_THRESHOLD
        MEMORY_USAGE_THRESHOLD
        DISK_SPACE_THRESHOLD

    Key Management:
        EXPIRATION: Number of years before key expiration.

    Security:
        TOKEN_SECURITY: Token for secure API access.

    Email Notifications:
        SMTP_SERVER
        SMTP_PORT
        SMTP_USER
        SMTP_PASSWORD
        ALERT_RECIPIENT

## 📊 Logging

Logs are maintained in crypto_controller.log with rotating file handlers to prevent excessive file sizes.

    Log Levels:
        INFO: General operational messages.
        DEBUG: Detailed diagnostic information.

## 📫 Contact

For any inquiries or support, please open an issue or contact [r6ty5r296it6tl4eg5m.constant214@passinbox.com](mailto:r6ty5r296it6tl4eg5m.constant214@passinbox.com).

---

## 📜 License

2024 - This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html). You are free to use, modify, and distribute this software under the terms of the GPL-3.0 license. For more details, please refer to the [LICENSE](../LICENSE) file included in this repository.
