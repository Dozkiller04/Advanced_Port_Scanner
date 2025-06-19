🔐 Advanced Python Port Scanner

This is a powerful and customizable **Advanced Port Scanner** built using Python. It performs **multi-threaded scanning**, **service detection**, **banner grabbing**, **SSL (HTTPS) fingerprinting**, and even **flags commonly vulnerable ports** — making it useful for educational and ethical security assessments.

---

📌 Features

- 🔍 Scan any target IP or hostname
- 🔢 Specify custom port range (1–65535)
- ⚡ Multi-threaded scanning using `ThreadPoolExecutor`
- 🧠 Service detection using `socket.getservbyport()`
- 🧾 Banner grabbing for open ports
- 🔐 SSL/TLS version detection for HTTPS (port 443)
- 🚨 Warns if dangerous ports like FTP, Telnet, SMB, etc. are open
- 📁 Saves results in `.txt` (human-readable) and `.csv` (for reports)

---

🖥️ Usage

🔧 Requirements:
- Python 3.x

▶️ Run the script:
```bash
python port_scanner.py
