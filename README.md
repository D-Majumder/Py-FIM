<h1 align="center" id="title">🧩 PyFIM (Guardian Edition) 🧩</h1>

<p align="center">
  <i>“A Real-Time File Integrity Monitoring & Guardian System — where Python defends your files like a Sentinel.”</i>
</p>

<p align="center">
  <img src="https://upload.wikimedia.org/wikipedia/commons/2/22/File_Manager_Windows_10_screenshot.png" alt="Cybersecurity Visual" style="max-width:100%;height:auto;border-radius:12px;box-shadow:0 0 15px rgba(0,150,255,0.3);">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" alt="Python Badge">
  <img src="https://img.shields.io/badge/watchdog-Library-green" alt="watchdog Badge">
  <img src="https://img.shields.io/badge/Platform-Windows-blueviolet" alt="Platform Badge">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" alt="License Badge">
</p>

---

<div align="center">
  <img src="https://img.shields.io/badge/🛡️_Real_Time_File_Guardian_-blue?style=for-the-badge" alt="Real-Time FIM Badge">
</div>

---

## ⚙️ About The Project

**PyFIM (Guardian Edition)** is a **File Integrity Monitoring (FIM)** tool written in Python — combining **real-time defense**, **secure baselines**, and **automatic restoration**.  
It was designed as an **educational cybersecurity project** to demonstrate how FIM systems detect and respond to file tampering.

> 🧠 *“It doesn’t just detect — it defends.”*

This version introduces **Guardian Mode**, which can instantly **restore or delete unauthorized changes**, ensuring critical files stay protected.

---

## 🚨 Features

✅ **Baseline Creation:** Scans directories and securely stores file hashes (SHA-256).  
✅ **Tamper Detection:** Detects new, modified, or deleted files against a verified baseline.  
✅ **Baseline Integrity Check:** Verifies its own hash before every scan to prevent tampering.  
✅ **Real-Time Monitoring:** Uses the `watchdog` library to detect changes as they happen.  
✅ **Guardian Mode:** Actively **restores deleted/modified files** or **removes unauthorized files**.  
✅ **Config-Driven:** Manage multiple monitoring jobs via `config.ini`.  
✅ **Secure Backups:** Automatically keeps copies of clean baseline files.  

---

## 🚀 Getting Started

### 🧩 Prerequisites

- Python 3.x  
- Required Python library:

```bash
pip install -r requirements.txt
(requirements.txt includes watchdog>=4.0.0)
```
---

## 💻 Installation

Clone this repository and navigate to the directory:

```bash
git clone https://github.com/D-Majumder/PyFIM.git
cd PyFIM
```
---

## ⚙️ Configuration

Create or edit your config.ini file. Example:

```init
[SystemFiles]
path = C:\Windows\System32
baseline_file = baseline_system32.json
ignore = *.log, *.tmp, *.cache

[MySecureFiles]
path = .\my_secret_files
baseline_file = baseline_myfiles.json
ignore = *.log, __pycache__*

[ProjectX]
path = C:\Users\Dhruba\Projects\ProjectX
baseline_file = baseline_projectx.json
ignore = .git*, *.pyc
```

Each section defines a Job — a monitored folder with its own baseline and ignore rules.

---

## ⚡ Usage

Run pyfim.py in one of three modes:

### 🏗️ 1. Initialize Baseline
>*python pyfim.py --mode init --job MySecureFiles --force*

Scans all files, creates a baseline JSON, verifies it, and backs up clean copies.

### 🔍 2. Check Integrity
>*python pyfim.py --mode check --job MySecureFiles*

Compares current file states with the stored baseline and reports any differences.

### 🛡️ 3. Real-Time Watch / Guardian Mode
>*python pyfim.py --mode watch --job MySecureFiles*


Begins real-time monitoring.
If set to Guardian Mode, the system will automatically restore or delete unauthorized files in real time.

`⚠️ Do not use --job ALL with watch mode — only one job can be actively watched.`

---

## 🧠 How It Works

- Hashes every file using SHA-256.
- Stores baseline in JSON with a .hash integrity checksum.
- Compares live state with baseline to detect changes.
- In Guardian Mode, automatically:
- Restores modified/deleted files from backup.
- Removes unauthorized new files.

---

## 🧪 Demo Scenarios
### 💾 1. Baseline Tampering

- Modify the baseline JSON manually.
- Run a scan → PyFIM detects the alteration and refuses to run.

### 🔄 2. Unauthorized Modification
- Edit a protected file → PyFIM instantly restores it (Guardian mode).

### 🧨 3. New File Injection
- Drop a new .exe in the monitored folder → PyFIM flags and deletes it.

---

## 🛠️ Built With

`Python 🐍`
`watchdog 🦴`
`hashlib, logging, json, configparser ⚙️`

--- 

## 📜 Disclaimer

This tool is for educational and research purposes only.
It is not a substitute for enterprise-grade security software.
Use responsibly and within controlled environments.

---

## 🤝 Connect With Us
<p align="center"> <a href="mailto:dhrubamajumder@proton.me" target="_blank"> <img src="https://img.shields.io/badge/Email-Dhruba%20Majumder-blue?logo=gmail" alt="Email Badge"> </a> <a href="https://www.linkedin.com/in/iamdhrubamajumder/" target="_blank"> <img src="https://img.shields.io/badge/LinkedIn-Dhruba%20Majumder-blue?logo=linkedin" alt="LinkedIn Badge"> </a> <a href="https://github.com/D-Majumder" target="_blank"> <img src="https://img.shields.io/badge/GitHub-D--Majumder-black?logo=github" alt="GitHub Badge"> </a> </p> <div align="center"> <img src="https://img.shields.io/badge/🚀_Built_for_Tech_Exhibitions_-_Learn_Securely_-green?style=for-the-badge" alt="Tech Exhibition Badge"> </div> <p align="center"> <img src="https://capsule-render.vercel.app/api?type=waving&color=1E90FF&height=100&section=footer&text=Defend+Your+Files,+Defend+Your+System.&fontSize=22&fontColor=111111&animation=fadeIn" /> </p>
