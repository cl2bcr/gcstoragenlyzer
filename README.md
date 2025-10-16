# GCS Storage Analyzer


[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Gitleaks](https://img.shields.io/badge/Gitleaks-Enabled-red.svg)](https://github.com/gitleaks/gitleaks)

**GCS Storage Analyzer** 🔍 - Deep scan your Google Cloud Storage buckets, detect public access risks, find sensitive data, and optimize costs. Run security audits with a single command and generate beautiful HTML reports!

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/cl2bcr/gcstoragenlyzer.git
cd gcstoragenlyzer

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # macOS/Linux
# Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
python setup.py install

# 4. Configure Google Cloud credentials (.env file)
echo "GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json" > .env

# 5. Install Gitleaks (for sensitive data scanning)
brew install gitleaks  # macOS
# Linux: wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz && tar -xzf gitleaks_linux_x64.tar.gz && sudo mv gitleaks /usr/local/bin/

# 6. Verify installation
gcstoragenlyzer --help
gitleaks version
```

---

## 🚀 Features

- 🔓 **Public Access Detection** - Scan buckets/folders/objects for public exposure
- 🔍 **Sensitive Data Finder** - Detect API keys, passwords, PII (Regex + Gitleaks)
- 📊 **Old Object Analysis** - Find objects older than any custom threshold for cost optimization
- 📈 **Beautiful HTML Reports** - Gradient UI, hover effects, responsive design
- 🌳 **Console Tree View** - Colorful bucket structure visualization
- ⚙️ **Custom Regex** - Add your own secret patterns

---

## 🛠️ Installation

### 1. Prerequisites

- Python 3.8+
- Google Cloud service account (Storage Object Viewer permission)
- Gitleaks (for sensitive data scanning)

### 2. Clone Repository

```bash
git clone https://github.com/cl2bcr/gcstoragenlyzer.git
cd gcstoragenlyzer
```

### 3. Virtual Environment

```bash
python -m venv venv

# Activation
source venv/bin/activate  # macOS/Linux
# Windows: venv\Scripts\activate
```

### 4. Dependencies

```bash
pip install -r requirements.txt
python setup.py install
```

### 5. Google Cloud Setup

```bash
# Create .env file
echo "GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json" > .env
```

### 6. Gitleaks Installation

**macOS:**
```bash
brew install gitleaks
```

**Linux:**
```bash
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
tar -xzf gitleaks_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
sudo chmod +x /usr/local/bin/gitleaks
```

**Windows:** Download from [Gitleaks Releases](https://github.com/gitleaks/gitleaks/releases)

### 7. Verification

```bash
gcstoragenlyzer --help
gitleaks version
```

---

## 📋 Usage

### Basic Commands

```bash
# List buckets
gcstoragenlyzer list buckets

# Display bucket tree
gcstoragenlyzer list tree --bucket my-bucket

# Scan for public access
gcstoragenlyzer scan expose --bucket my-bucket
gcstoragenlyzer scan expose --all

# Scan for sensitive data
gcstoragenlyzer scan sensitive --bucket my-bucket --public

# Analyze old objects
gcstoragenlyzer scan old --bucket my-bucket --day 30
```

### Reporting

```bash
# Generate HTML report
gcstoragenlyzer scan expose --all --output-format html --output-file report.html

# JSON output
gcstoragenlyzer scan sensitive --bucket my-bucket --json-output

# Scan specific file types
gcstoragenlyzer scan sensitive --bucket my-bucket --file-type .env,.txt,.log
```

### Advanced Options

```bash
--output-format [text|json|html]     # Output format
--output-file report.html            # Save to file
--public                             # Only public objects
--file-type .env,.txt                # File filter
--day 30                             # Day threshold
--no-mask                            # Unmasked output (⚠️)
--exclude-gitleaks                   # Skip Gitleaks
```

---

## 📊 Sample Outputs

### Console Tree

```
🌳 my-bucket:
📁 docs/ (PUBLIC 🚨)
├── 📄 config.env (2.5 KB)
└── 📁 images/
    └── 📄 logo.png (45 KB)
📄 data.csv (PRIVATE ✅, 1.2 MB)
```

### Sensitive Data Report

```
🔍 3 sensitive findings detected:
📄 config.env:
  - AWS Key: AKIA...ABCD ✅
  - Email: admin@company.com
📄 db.conf:
  - Password: mysql...123 ✅
```

---

## 📈 HTML Reports

HTML reports include:

- 🎨 Gradient backgrounds and modern UI
- 🖱️ Hover effects and interactive tables
- 🏷️ Status badges (CRITICAL/WARNING/SAFE)
- 📱 Responsive design
- 🌳 Access tree visualization
- 📊 Statistics cards
- 🔍 Detailed findings list

```bash
gcstoragenlyzer scan expose --bucket my-bucket --output-format html --output-file security.html
```

---

## 📄 License

<img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License">

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 🙌 Built With

- 🐍 Python 3.8+
- ☁️ Google Cloud Storage API
- ⚙️ Click CLI Framework
- 🔍 Gitleaks Secret Scanner
- 📊 Custom HTML Engine
- 🌈 Rich Console Library

---

## 📞 Contact

For questions or suggestions:

- 🐛 [Open an issue](https://github.com/cl2bcr/gcstoragenlyzer/issues)
- 💬 [Discussions](https://github.com/cl2bcr/gcstoragenlyzer/discussions)
- 📧 Email: celebibicer1@gmail.com

---
