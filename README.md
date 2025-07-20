# Living Off The Land (LOTL)

<div align="center">
  <img src="https://img.shields.io/badge/version-v1.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/license-BSD-green" alt="License">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey" alt="Platform">
  <img src="https://img.shields.io/badge/language-C%2B%2B20-orange" alt="Language">
  <img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build">
</div>

<p align="center">
  <b>Advanced Security Enumeration and Privilege Escalation Tool</b><br>
  <sub>Developed by <a href="https://github.com/ibrahmsql">ibrahimsql</a></sub>
</p>
 

## 🔍 Overview

**Living Off The Land (LOTL)** is a comprehensive security enumeration and privilege escalation tool for Linux and macOS systems. Inspired by tools like LinPEAS and LSE, LOTL automates the discovery of security vulnerabilities, misconfigurations, and privilege escalation vectors, making it an essential tool for security professionals, penetration testers, and system administrators.

The tool performs thorough system analysis without requiring user interaction, providing detailed, color-coded output to highlight security issues based on their severity.

## ✨ Key Features

### System Security Analysis
- **Full System Enumeration**: Comprehensive scan of system configuration and security settings
- **Privilege Escalation Detection**: Identifies potential vectors for privilege escalation
- **Permission Analysis**: Discovers and analyzes SUID/SGID files and world-writable directories
- **Credential Discovery**: Locates exposed credentials and sensitive configuration files

### Advanced Security Checks
- **Sudo Rule Analysis**: Detects exploitable sudo configurations and misconfigurations
- **Cron Job Analysis**: Identifies writable or exploitable scheduled tasks
- **Kernel Vulnerability Scanning**: Checks kernel version against known vulnerabilities
- **CVE Detection**: Includes specific scanning for CVES vulnerabilities

### Environment Analysis
- **Container Detection**: Identifies container environments and potential escape vectors
- **Docker Security**: Analyzes Docker configurations and security issues
- **Network Reconnaissance**: Examines network interfaces, connections, and open ports
- **Service Enumeration**: Discovers running services and potential misconfigurations

### User Experience
- **Automatic Mode**: Runs all checks without requiring user interaction
- **Color-Coded Output**: Easy-to-read results with color highlighting based on severity
- **Detailed Reporting**: Comprehensive output with explanations and remediation suggestions
- **Multithreaded Scanning**: Fast execution with parallel processing capabilities

## 🚀 Installation

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/ibrahmsql/LivingOfTheLand.git

# Navigate to the directory
cd LivingOfTheLand

# Run the installation script
chmod +x install_lotl.sh
./install_lotl.sh
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/ibrahmsql/LivingOfTheLand.git

# Navigate to the directory
cd LivingOfTheLand

# Compile the tool
make clean
make

# Make executable
chmod +x lotl
```

## 📋 Usage

LOTL is designed to run automatically without requiring user interaction:

```bash
# Run full system scan
./lotl

# Run with elevated privileges (recommended for complete results)
sudo ./lotl
```

### Output Interpretation

The output is color-coded for easy interpretation:
- **Red**: High-severity issues that require immediate attention
- **Yellow**: Medium-severity issues that should be investigated
- **Green**: Low-severity issues or informational items
- **Blue**: Section headers and tool information
- **Cyan**: Commands and technical details

## 🔧 System Requirements

- **Operating System**: Linux (Debian, Ubuntu, CentOS, RHEL, Arch) or macOS
- **Compiler**: GCC 10+ or Clang 10+ with C++20 support
- **Dependencies**: make, standard system utilities

## 🌐 Recommended Tools

For comprehensive security testing, we recommend pairing LOTL with these tools:

### [Gocat](https://github.com/ibrahmsql/Gocat.git)
A modern, cross-platform netcat alternative written in Go with enhanced features for network communication and security testing.

**Key Gocat Features:**
- Advanced port scanning with service detection
- Secure connections with SSL/TLS support
- Proxy support (SOCKS5, HTTP)
- File transfer with progress monitoring
- Interactive shell capabilities
- Cross-platform compatibility (Linux, macOS, Windows)

### Other Recommended Tools
- **LinPEAS**: Linux Privilege Escalation Awesome Script
- **LSE**: Linux Smart Enumeration
- **pspy**: Process monitoring without root permissions
- **GTFOBins**: Unix binaries that can be exploited for privilege escalation

## 📊 CVE Coverage

LOTL includes specific scanning for recent sudo vulnerabilities:

### CVE-2025-32462
A policy-check flaw in sudo that allows attackers to bypass host checks and execute commands as root. Affects sudo versions 1.8.8 through 1.9.17.

### CVE-2025-32463
The "chroot to root" vulnerability in sudo that allows attackers to load malicious libraries with root privileges. Affects sudo versions 1.9.14 through 1.9.17.

## 🛠️ Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the BSD License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for educational and legitimate security assessment purposes only. Always obtain proper authorization before running security tools on systems you don't own or have explicit permission to test.

## 📧 Contact

- **Author**: ibrahimsql
- **GitHub**: [https://github.com/ibrahimsql](https://github.com/ibrahimsql)

---

<p align="center">
  <sub>Made with ❤️ by ibrahimsql</sub>
</p> 
