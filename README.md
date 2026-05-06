# EchoPurge 🔍

> **Advanced Duplicate File Hunter & Purger**  
> Made by [Monish Paramasivam](https://github.com/monishparamasivam)

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)]()

```
╔═══════════════════════════════════════════════════════════════╗
║    ███████╗ ██████╗██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗██████╗ ║
║    ██╔════╝██╔════╝██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔══██╗║
║    █████╗  ██║     ███████║██║   ██║██████╔╝██║   ██║██║  ██║║
║    ██╔══╝  ██║     ██╔══██║██║   ██║██╔═══╝ ██║   ██║██║  ██║║
║    ███████╗╚██████╗██║  ██║╚██████╔╝██║     ╚██████╔╝██████╔╝║
║    ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═════╝ ║
╚═══════════════════════════════════════════════════════════════╝
```

EchoPurge uses a **3-pass detection engine** to find and remove duplicate files with zero false positives — fast, safe, and fully scriptable.

---

## ✨ Features

- **3-Pass Detection** — size grouping → quick partial hash → full cryptographic hash
- **Parallel Hashing** — multi-threaded for large directories
- **Smart Keep Strategies** — keep the newest, oldest, shortest, or longest-path copy
- **Safe Trash Mode** — move duplicates to a folder instead of permanent deletion
- **Dry-Run Mode** — simulate everything; nothing is touched
- **JSON Reports** — full audit trail of every duplicate found
- **Extension & Size Filters** — scan only what you care about
- **Interactive Review** — confirm each group before deletion
- **Auto Mode** — fully non-interactive for scripts and pipelines
- **Zero Dependencies** — pure Python standard library

---

## 📦 Installation

```bash
# Clone the repo
git clone https://github.com/monishparamasivam/echopurge.git
cd echopurge

# (Optional) make it executable
chmod +x echopurge.py

# (Optional) add to PATH
sudo ln -s $(pwd)/echopurge.py /usr/local/bin/echopurge
```

**Requirements:** Python 3.7+ — no pip installs needed.

---

## 🚀 Quick Start

```bash
# Scan a folder interactively
python echopurge.py scan ~/Downloads

# Scan and auto-delete, keeping the newest copy
python echopurge.py scan ~/Downloads --auto

# Safe dry-run — see what WOULD be deleted
python echopurge.py scan ~/Downloads --dry-run
```

---

## 📖 Usage

```
python echopurge.py scan <PATH> [OPTIONS]
```

### Options

| Flag | Description |
|---|---|
| `--ext .jpg .png` | Only scan files with these extensions |
| `--min-size 1MB` | Skip files smaller than this size |
| `--max-size 2GB` | Skip files larger than this size |
| `--exclude DIR` | Exclude one or more directories |
| `--algorithm sha256` | Hash algorithm: `md5`, `sha1`, `sha256`, `sha512` |
| `--workers 8` | Number of parallel threads (default: 4) |
| `--strategy newest` | Which copy to **keep**: `newest`, `oldest`, `shortest_path`, `longest_path` |
| `--auto` | Auto-delete without prompting |
| `--dry-run` | Simulate deletions — no files removed |
| `--trash DIR` | Move dupes here instead of deleting permanently |
| `--report out.json` | Save a JSON report of all duplicates found |
| `--follow-symlinks` | Follow symbolic links during scan |
| `--no-banner` | Hide the ASCII banner |

---

## 💡 Examples

```bash
# Find duplicate photos, keep oldest, dry-run first
python echopurge.py scan ~/Photos --ext .jpg .jpeg .png --strategy oldest --dry-run

# Auto-clean a downloads folder, move dupes to trash
python echopurge.py scan ~/Downloads --auto --trash ~/echopurge_trash

# Scan multiple directories, save JSON report
python echopurge.py scan /data/proj1 /data/proj2 --report dupes.json

# Fast scan of large media library using 8 threads + MD5
python echopurge.py scan /media --ext .mp4 .mkv --workers 8 --algorithm md5

# Minimal output for cron/pipeline
python echopurge.py scan /backups --auto --no-banner --dry-run
```

---

## 🔬 How It Works

EchoPurge uses a **3-pass pipeline** to minimise disk reads:

```
All Files
   │
   ▼
[Pass 1] Group by file size          ← eliminates ~90% of files instantly
   │
   ▼
[Pass 2] Quick hash (first+last 4KB) ← cheap pre-filter, parallel
   │
   ▼
[Pass 3] Full cryptographic hash     ← only true candidates, parallel
   │
   ▼
Duplicate Groups → Review / Auto-delete
```

This means even a 100 GB media library only fully hashes a small fraction of files.

---

## 📄 JSON Report Format

```json
{
  "generated_at": "2026-05-06T14:30:00",
  "tool": "EchoPurge by Monish Paramasivam",
  "total_groups": 3,
  "total_duplicates": 7,
  "wasted_bytes": 52428800,
  "groups": [
    {
      "hash": "a3f5...",
      "file_size_bytes": 4096000,
      "file_size_human": "4.00 MB",
      "copies": 3,
      "files": ["/path/a.jpg", "/path/b.jpg", "/path/c.jpg"]
    }
  ]
}
```

---

## ⚠️ Safety Notes

- **Always run `--dry-run` first** on important directories.
- Use `--trash DIR` for recoverable deletion instead of permanent removal.
- EchoPurge will ask for a `YES` confirmation before any permanent deletion.
- Hard-linked files (same inode) are never double-counted.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">Made with ❤️ by <strong>Monish Paramasivam</strong></p>
