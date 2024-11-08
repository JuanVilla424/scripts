# 🗄️ Scripts Repository

![CI/CD](https://img.shields.io/badge/CI/CD-Pipeline-blue)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)
![Build Status](https://github.com/JuanVilla424/scripts/actions/workflows/ci.yml/badge.svg?branch=main)
![Status](https://img.shields.io/badge/Status-Stable-green.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE.md)

This repository contains a collection of base Python scripts that are invoked by the CI/CD processes of other repositories, especially the template repository. These scripts are used for formatting, checking files, version control, and updating the year in file headers or documentation.

## 📚 Table of Contents

- [Features](#-features)
- [Getting Started](#-getting-started)
  - [Installation](#-installation)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

## 🌟 Features

- **Formatting Scripts**: Format code files according to specified style guidelines.
- **File Checking Scripts**: Check files for compliance, correctness, and other criteria.
- **Version Control Scripts**: Manage version numbers in your project.
- **Year Update Scripts**: Update the year in file headers or documentation.

## 🚀 Getting Started

To use these scripts in your project, add this repository as a submodule.

### 🔨 Installation

1. Add the scripts repository as a submodule in your project:

   ```bash
   git submodule add https://github.com/JuanVilla424/scripts.git
   ```

   or, using branch

   ```bash
   git submodule add -b <branch_name> https://github.com/JuanVilla424/scripts.git
   ```

2. Update the submodule when there are changes:

   ```bash
   git submodule update --remote --merge
   ```

## 🤝 Contributing

**Contributions are welcome! To contribute to this repository, please follow these steps**:

1. **Fork the Repository**

2. **Create a Feature Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Commit Your Changes**

   ```bash
   git commit -m "feat(<scope>): your feature commit message - lower case"
   ```

4. **Push to the Branch**

   ```bash
   git push origin feature/your-feature-name
   ```

5. **Open a Pull Request into** `dev` **branch**

Please ensure your contributions adhere to the Code of Conduct and Contribution Guidelines.

### 🔧 Environment Setup

**Mandatory: Setting Up a Python Virtual Environment**

Setting up a Python virtual environment ensures that dependencies are managed effectively and do not interfere with other projects.

1. **Create a Virtual Environment**

   ```bash
   python -m venv venv
   ```

2. **Activate the Virtual Environment**

   On Unix or MacOS:

   ```bash
   source venv/bin/activate
   ```

   On Windows:

   ```bash
    powershell.exe -ExecutionPolicy Bypass -File .\venv\Scripts\Activate.ps1
   ```

3. **Upgrade pip**

   ```bash
   python -m ensurepip
   pip install --upgrade pip
   ```

4. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   pip install poetry
   poetry lock
   poetry install
   ```

   - Deactivate the Virtual Environment

   When you're done, deactivate the environment:

   ```bash
    deactivate
   ```

### 🛸 Pre-Commit Hooks

**Install and check pre-commit hooks**: MD files changes countermeasures, python format, python lint, yaml format, yaml lint, version control hook, changelog auto-generation

```bash
pre-commit install
pre-commit install -t pre-commit
pre-commit install -t pre-push
pre-commit autoupdate
pre-commit run --all-files
```

## 📫 Contact

For any inquiries or support, please open an issue or contact [r6ty5r296it6tl4eg5m.constant214@passinbox.com](mailto:r6ty5r296it6tl4eg5m.constant214@passinbox.com).

---

## 📜 License

2024 - This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html). You are free to use, modify, and distribute this software under the terms of the GPL-3.0 license. For more details, please refer to the [LICENSE](LICENSE.md) file included in this repository.
