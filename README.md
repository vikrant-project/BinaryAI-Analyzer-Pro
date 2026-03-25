# 🛡️ BinaryAI Analyzer Pro v2.0
> **The ultimate AI-driven companion for Android Reverse Engineering & Anti-Cheat Research.**

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://www.python.org/)
[![Radare2](https://img.shields.io/badge/Backend-Radare2-red)](https://rada.re/n/)
[![AI-Powered](https://img.shields.io/badge/AI-DeepSeek%20%2F%20OpenRouter-green)](https://deepseek.com/)

---

## 🔍 What is this Code?
**BinaryAI Analyzer Pro** is an advanced Telegram-based automation bot designed to bridge the gap between static binary analysis and modern Artificial Intelligence. It consumes `.so` (Shared Object) libraries and decompiled `.c` files to automatically identify security routines and generate functional bypass code.

By utilizing **Radare2** for deep binary inspection and **Dual-Engine AI (DeepSeek + OpenRouter)** for logic generation, it automates the most tedious parts of reverse engineering.

---

## 🚀 Why Use It?
Manual reverse engineering of modern game anti-cheats is time-consuming. This tool provides:
* **Instant Analysis:** What takes a human hours (finding ban/kick logic), the bot does in seconds.
* **Zero Repetition:** It remembers previously extracted addresses so you always get fresh results.
* **Bypass Ready:** It doesn't just find functions; it writes the `PATCH_LIB` and `HOOK_LIB` code for you.

---

## 💎 Importance
In the world of cybersecurity and game modding, **speed is everything.**
1.  **Anti-Cheat Research:** Rapidly identify `anogs`, `TP`, or `GVoice` security signatures.
2.  **Educational Value:** Learn how high-level C logic translates into assembly offsets.
3.  **Efficiency:** Automated parallel processing allows the bot to handle massive `.so` files without crashing.

---

## ⚙️ How It Works
The bot follows a sophisticated multi-stage pipeline:

1.  **Extraction:** Uses `Radare2` in parallel threads to pull exports, imports, strings, and symbols.
2.  **Contextualization:** Chunks the data so it fits within AI token limits without losing "context."
3.  **AI Intelligence:** * **Primary (DeepSeek):** High-speed logic processing.
    * **Fallback (OpenRouter):** Ensures 100% uptime if primary APIs are busy.
4.  **Code Synthesis:** Generates unique C++ hooks with randomized bypass strategies (Return value manipulation, NOPing, or Flag spoofing).

---

## 📊 Comparison: Why Pro?

| Feature | Standard Manual RCE | BinaryAI Analyzer Pro |
| :--- | :--- | :--- |
| **Speed** | 1-2 Hours per file | < 2 Minutes |
| **Logic Gen** | Manual Coding | AI-Generated Hooks |
| **Search** | Manual Grep/String find | AI-Contextual search |
| **Uptime** | Limited by Human fatigue | 24/7 Dual-API Fallback |
| **Duplicates** | Easy to lose track | History-aware (No repeats) |

---

## 🛠️ Installation & Setup

### 1. Prerequisites
* **Linux Server** (Ubuntu 20.04+ recommended)
* **Python 3.10+**
* **Radare2:** `sudo apt-get install radare2`

### 2. Clone & Install
```bash
git clone [https://github.com/vikrant-project/BinaryAI-Analyzer-Pro.git](https://github.com/vikrant-project/BinaryAI-Analyzer-Pro.git)
cd BinaryAI-Analyzer-Pro
pip install -r requirements.txt
```

### 3. Configuration
Open `analyzer_bot.py` and update the following:
* `OWNER_ID`: Your Telegram User ID.
* `TELEGRAM_BOT_TOKEN`: Your bot token from @BotFather.
* `API_KEYS`: Input your DeepSeek and OpenRouter keys.

### 4. Running the Bot
```bash
python3 analyzer_bot.py
```

---

## 🎨 High-End UI Preview
The bot utilizes **Inline Keyboards** and **HTML-formatted Status Windows**:
* `[👤 Approve User]` | `[🚫 Disapprove]`
* `[📤 Analyze .so]` | `[📄 Analyze .c]`

Every analysis displays a sleek loading bar and professional "Processing" headers to keep the user engaged.

---
**Disclaimer:** This tool is for educational and research purposes only. The developers are not responsible for any misuse.
```
