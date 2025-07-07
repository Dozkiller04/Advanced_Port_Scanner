# 🔍 Advanced Python Port Scanner

A Python-based port scanner tool that allows users to scan specific IP addresses or hostnames for open ports.  
It helps in identifying active services and analyzing potential security risks on a network.

---

## ✨ Features

- 📡 Scan custom IP addresses or hostnames
- 🔢 Specify start and end port range
- 📊 Displays open ports with brief service information
- 🧠 Fast scanning with multithreading
- 💾 Saves output to `.txt` and `.csv` formats
- 🧑‍💻 Beginner-friendly CLI interface

---

## 🛠️ Technologies Used

- 🐍 Python 3.x
- ⚙️ `socket` – for scanning ports
- 📁 `csv` & `datetime` – for saving logs
- 🚀 `threading` – for fast parallel scans

---

## Requirements
- Python 3.10+
- Internet connection for scanning


## 📁 Folder Structure
Advanced_Port_Scanner/
├── Port_Scanner.py # Main script
├── scan_results.txt # Sample text result
├── scan_results.csv # Sample CSV result
├── screenshots/ # Output screenshots
│ ├── 01_script_start.png
│ └── 02_scan_result.png
└── README.md # Project documentation


---

## ⚙️ How to Run

```bash
git clone https://github.com/Dozkiller04/Advanced_Port_Scanner.git
cd Advanced_Port_Scanner

python Port_Scanner.py
Enter target (e.g. google.com or 192.168.1.1)
Enter start port (e.g. 20)
Enter end port (e.g. 100)

Results will show in console and be saved to scan_results.txt and scan_results.csv.
```
## 📸 Screenshots

### ▶️ Script Start Prompt  
[![Script Start](https://raw.githubusercontent.com/Dozkiller04/Advanced_Port_Scanner/main/screenshots/01_script_start.png.png)](https://github.com/Dozkiller04/Advanced_Port_Scanner/blob/main/screenshots/01_script_start.png.png)

### ✅ Open Port Scan Output  
[![Scan Output](https://raw.githubusercontent.com/Dozkiller04/Advanced_Port_Scanner/main/screenshots/02_scan_result.png.png)](https://github.com/Dozkiller04/Advanced_Port_Scanner/blob/main/screenshots/02_scan_result.png.png)


---

## 🎬 Project Demo (with Voice-over)

📽️ **Watch full demo:**  
👉 [Click to Watch on Google Drive](https://drive.google.com/file/d/11nu8dicrcWvslHTbP3ZMoWO3aYMYD1We/view?usp=drive_link)

---

## 🚀 Future Improvements

- 🌐 Service version detection  
- 🛑 Port exclusion filters  
- 📈 GUI using Tkinter or PyQt  
- 🧠 Add UDP scanning support  
- 🔐 Detect common vulnerable ports

---
# Advanced Port Scanner 🔎
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

## 👨‍💻 Author

**Soham Pramod Tayade**  
🎓 BSc Cyber & Digital Science  
🏢 RISE Internship – Cybersecurity & Ethical Hacking  
📍 Pune, Maharashtra  
🔗 GitHub: [Dozkiller04](https://github.com/Dozkiller04)
