# 🛡️ AuthFlow Analyzer Pro
[![Burp Suite](https://img.shields.io/badge/Burp-Suite-orange?style=flat-square&logo=portswigger)](https://portswigger.net/burp)
[![Python](https://img.shields.io/badge/Python-2.7%20(Jython)-blue?style=flat-square&logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**AuthFlow Analyzer Pro** is a powerful Burp Suite extension designed to streamline the analysis of authentication and authorization flows. It allows security researchers to compare how different user profiles respond to the same requests in real-time and provides an automated engine to handle session expiration and token regeneration.

[Key Features](#-key-features) • [Installation](#-installation) • [Usage Guide](#-usage-guide) • [Contributing](#-contributing)

---

## ✨ Key Features

- **🚀 Multi-Profile Mirroring**: Automatically clone and send intercepted requests through multiple configured profiles (e.g., Admin, User, Guest) to detect IDOR and broken access control.
- **🔄 Smart ATOR (Automatic Token On Response)**: 
    - Detects session expiration using custom triggers (Status Code or Body content).
    - Automatically executes a regeneration request to fetch a new token.
    - Seamlessly updates subsequent requests with the fresh credentials.
- **📊 Comparative Analysis View**: A dedicated dashboard to view side-by-side responses, highlighted by status code colors for quick triage.
- **💾 Configuration Persistence**: Save and load your complex testing environments into JSON profiles.
- **🔍 Advanced Filtering**: Search and filter through thousands of results instantly.
- **📜 Detailed Logging**: Full traceability of authentication events and network activities.

## 🛠 Installation

### Prerequisites
1. **Burp Suite** (Community or Professional).
2. **Jython Standalone JAR**: This extension requires Jython to run Python inside Burp.
    - Download it from [Jython.org](https://www.jython.org/download).
    - Configure it in Burp: `Extender` -> `Options` -> `Python Environment`.

### Setup
1. Download the `AuthFlowAnalyzer.py` file.
2. In Burp Suite, go to the `Extensions` tab.
3. Click **Add**.
4. Select `Extension type`: **Python**.
5. Select the `AuthFlowAnalyzer.py` file and click **Next**.

## 📖 Usage Guide

### 1. Configure Profiles
- Navigate to the **AuthFlow** tab -> **Config**.
- Add a new Profile (e.g., "Manager-User").
- Add headers you want to replace (e.g., `Authorization: Bearer ...` or `Cookie: session=...`).

### 2. Set Up Token Regeneration (ATOR)
- Enable **ATOR Regeneration**.
- Paste the raw "Login" or "Refresh" request.
- Define the **Token Start (Pre)** and **Token End (Post)** strings to extract the new token from the response.
- Set the **Trigger Condition** (e.g., `401` or `Unauthorized`).

### 3. Analyze Results
- Once enabled, every request from Proxy/Repeater will be mirrored.
- Go to the **Results** tab to compare status codes across your defined profiles.

## 🤝 Contributing

Contributions are welcome! If you have ideas for new features or find a bug:
1. Fork the Project.
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`).
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the Branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## ⚖️ License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Developed for security professionals.*
