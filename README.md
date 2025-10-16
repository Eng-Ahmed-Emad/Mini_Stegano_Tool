# 🕵️‍♂️ stegano_exe
**Python Steganography Tool for Executables**

This tool allows you to **hide**, **extract**, and **detect** secret data inside executable files (`.exe`) using **AES encryption** for confidentiality.

---

## ⚙️ Requirements

- Python 3.8 or higher  
- [PyCryptodome](https://pypi.org/project/pycryptodome/)

### 🔧 Install Dependencies
```bash
pip install pycryptodome
```

---

## 🚀 How to Use

### 🟢 Hide a File Inside an Executable
```bash
python stegano_exe.py hide --carrier carrier.exe --secret secret.txt --output hidden.exe --password mypass123
```
**Explanation:**
- `--carrier` → Path to the original executable file  
- `--secret` → File you want to hide  
- `--output` → Name/path of the output stego executable  
- `--password` → Encryption password (optional but recommended)

---

### 🟣 Extract a Hidden File
```bash
python stegano_exe.py extract --carrier hidden.exe --secret extracted_secret.txt --password mypass123
```
**Explanation:**
- `--carrier` → The executable that contains hidden data  
- `--secret` → Output path for the recovered file  
- `--password` → Password used during hiding

---

### 🟠 Detect if an Executable Contains Hidden Data
```bash
python stegano_exe.py detect --carrier hidden.exe
```
**Explanation:**
- This checks whether the specified `.exe` contains any embedded data.

---

## 🧠 Example
```bash
python stegano_exe.py hide --carrier calc.exe --secret note.txt --output calc_hidden.exe --password 1234
python stegano_exe.py extract --carrier calc_hidden.exe --secret recovered.txt --password 1234
python stegano_exe.py detect --carrier calc_hidden.exe
```

---

## 🧰 Notes
- Works only with **Windows PE (.exe)** files.  
- AES-256 encryption is used for secure data hiding.  
- Avoid hiding very large files as it increases the EXE size significantly.  

---

## 🧩 Troubleshooting

### 🔸 Error: `ModuleNotFoundError: No module named 'Crypto'`
➡️ Solution: Install PyCryptodome using:
```bash
pip install pycryptodome
```

### 🔸 Error: `stegano_exe.py: error: the following arguments are required: action`
➡️ Solution: Add one of the required actions: `hide`, `extract`, or `detect`.

---

## 👨‍💻 Author
Developed by **Ahmed Emad Eldeen Abdelmoneam**  
Computer Science Student @ Banha University  
Specializing in **Information Security & Digital Forensics**
