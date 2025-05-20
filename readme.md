## 🔍 Overview

ShadowScan is a powerful web scanning tool that combines two essential security modules:

1. **EnvHunter** - Hunts for exposed .env files and secrets
2. **XSSAutoFuzz** - Advanced XSS vulnerability detection

Created by **Lenny**, this tool is designed for pentesters, security researchers, and developers concerned about the security of their web applications.

## ✨ Features

### 🕵️ EnvHunter Module
- Multi-path scanning for .env files
- Detection of 15+ secret types (API keys, credentials, etc.)
- Advanced regex patterns for extraction
- Support for file variants (.env.local, .env.prod, etc.)

### 🎯 XSSAutoFuzz ​​Module
- 20+ predefined XSS payloads
- Multi-parameter fuzzing (GET/POST)
- Intelligent reflection detection
- Multithreading for increased performance
- HTML form parsing
- Automatic basic crawling

### 🛠️ Options

| Option | Description                             |
| ------ | --------------------------------------- |
| `-a`   | Run all scans (EnvHunter + XSSAutoFuzz) |
| `-e`   | Run only the EnvHunter module           |
| `-x`   | Run only the XSSAutoFuzz module         |
| `-t`   | Number of threads to use (default: 20)  |
| `-o`   | Save the results to a JSON file         |
| `-v`   | Enable verbose mode                     |

