# Messenger Memory Forensics

A desktop tool for batch analysis of memory images and process dumps from Signal, WhatsApp, Telegram, and Viber. It recursively scans an input folder, writes a CSV for every selected file, and saves a run summary. Signal, WhatsApp, and Telegram runs also produce a deduplicated `messages_unique.csv`.

The parsers were developed for controlled memory-forensics experiments. Their signatures and structure checks may depend on application version and memory layout. Treat recovered records as candidates and verify them against the source bytes before drawing forensic conclusions.

## Requirements

- Python 3.10 or later; use a 64-bit build for large memory images.
- PyQt5 5.15, installed through `requirements.txt`, for the desktop interface.
- `openpyxl` only for the standalone Viber XLSX exporter. The batch GUI writes CSV and does not require it.

The batch worker and parsers otherwise use the Python standard library.

## Quick start

In PowerShell:

```powershell
git clone https://github.com/seturi/Messenger-Memory-Forensics.git
cd Messenger-Memory-Forensics
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe batch_analysis_gui.py
```

On macOS or Linux, use `.venv/bin/python` in place of `.\.venv\Scripts\python.exe`.

## Basic usage

1. Select the folder containing memory files and a different folder for results.
2. Choose **Signal**, **WhatsApp**, **Telegram**, or **Viber**. Keep the default extensions or enter the extensions to scan.
3. Click **Start analysis**. Open the results folder when the run finishes.

Each run creates a timestamped folder containing `run.json`, `summary.csv`, and one CSV per input file under `results/`. Signal, WhatsApp, and Telegram runs also create `messages_unique.csv`. A CSV header is written even when a file yields no records.

For large collections, **Fast analysis** scans only `.dmp` files. Signal's **Main PID** setting defaults to **Any PID**; enter a PID only to restrict process dumps to filenames ending in `_<PID>.dmp`. **Include partial structures** adds lower-confidence Signal and WhatsApp evidence.

The GUI retains completed CSVs when a run is cancelled. Output folders nested under the input folder are excluded from scanning.

## Repository layout

```text
batch_analysis_gui.py   Desktop interface and batch worker
parsers/                Active Signal, WhatsApp, Telegram, and Viber parsers
tests/                  Synthetic integration checks
```

Historical parsers, local research scripts, memory captures, and generated results are intentionally excluded from this public release. The repository does not contain sample user messages or source dumps.
