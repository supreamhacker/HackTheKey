# 🚀 HackTheKey

HackTheKey is power full and profficional api key validation tool. Use this tool only Ethically and authorized target.

**The Ultimate API Key Validator, Auditor & Permission Extractor.**

[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/hackthekey)](https://goreportcard.com/report/github.com/yourusername/hackthekey)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`HackTheKey` is a high-performance, concurrent cybersecurity tool written in **Golang**. It identifies, validates, and extracts permissions for exposed API keys across major platforms (AWS, Stripe, GitHub, OpenAI, Slack, etc.) in milliseconds, while featuring smart rate-limiting to avoid IP bans.

## ✨ Features

- 🔍 **Smart Regex Identification:** Instantly identifies the platform of an API key.
- 🌐 **Multi-Endpoint Deep Scanning:** Hits multiple endpoints simultaneously to find exact access levels.
- ⚡ **Blazing Fast Concurrency:** Utilizes Go's Goroutines for sub-second scans.
- 🛡️ **Built-in Rate Limiting:** `-delay` flag prevents aggressive scanning from triggering 429 Rate Limit blocks.
- 🧠 **Dynamic Error Parsing:** Extracts exact reasons like "IP Restricted" or "Expired Token" instead of generic errors.
- 📊 **Scope & Permission Extraction:** Identifies Read, Write, or Admin access (e.g., GitHub `X-OAuth-Scopes`).
- 🎨 **Beautiful CLI Output:** Color-coded terminal output for easy reading.

## 📦 Installation

### Method 1: The Pro Way (Recommended) 🚀
If you have Go installed, install `HackTheKey` directly from GitHub with a single command:

```bash
go install github.com/supreamhacker/hackthekey@latest


Method 2: Build from Source

git clone https://github.com/supreamhacker/hackthekey.git
cd hackthekey
go mod tidy
go build -o hackthekey main.go

🛠️ Usage
Scan a Single Key

hackthekey -k "sk_live_1234567890abcdef"


Scan with Rate Limiting (Avoid IP Bans)

hackthekey -k "ghp_abcde1234567890abcde1234567890abcde" -delay 500ms


Export Results to JSON or TXT


hackthekey -k "xoxb-123456789" -o results.json
hackthekey -k "SG.abcdef..." -o target.txt


Help Menu

hackthekey -h


⚙️ Configuration

The tool uses a signatures.json file to store platform regex patterns and endpoints. You can easily add new platforms by editing this JSON file without recompiling the Go code.

⚠️ Disclaimer & Ethical Use

HackTheKey is intended strictly for Educational Purposes, Authorized Bug Bounty Hunting, and Internal Security Auditing.
DO NOT use this tool to test API keys that you do not own or have explicit permission to test.
The authors are not responsible for any misuse or damage caused by this tool. Use it responsibly. 🛡️



