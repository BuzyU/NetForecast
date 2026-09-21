"""
CIC-IDS2017 Dataset Downloader
Downloads the 8 official CIC-IDS2017 CSV files from Hugging Face mirror
into data/raw_cicids/ with streaming and progress reporting.
"""

import os
import sys
import time
import urllib.request
from pathlib import Path

FILES = [
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv"
]

BASE_URL = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/{filename}?download=true"

def download_file(filename: str, dest_dir: Path, idx: int, total: int):
    url = BASE_URL.format(filename=filename)
    dest_file = dest_dir / filename
    tmp_file = dest_dir / f"{filename}.tmp"

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    req = urllib.request.Request(url, headers=headers)

    # Get remote size
    try:
        with urllib.request.urlopen(req) as resp:
            total_bytes = int(resp.headers.get("Content-Length", 0))
    except Exception as e:
        print(f"[{idx}/{total}] ERROR getting info for {filename}: {e}")
        return False

    # Check if already complete
    if dest_file.exists() and dest_file.stat().st_size == total_bytes:
        print(f"[{idx}/{total}] {filename} already downloaded ({total_bytes / (1024*1024):.2f} MB). Skipping.")
        return True

    print(f"[{idx}/{total}] Downloading {filename} ({total_bytes / (1024*1024):.2f} MB)...")
    start_time = time.time()
    downloaded = 0
    chunk_size = 1024 * 1024  # 1 MB

    try:
        with urllib.request.urlopen(req) as resp, open(tmp_file, "wb") as out_f:
            last_print = time.time()
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                out_f.write(chunk)
                downloaded += len(chunk)
                
                # Print progress every 1.5 seconds
                now = time.time()
                if now - last_print > 1.5 or downloaded == total_bytes:
                    pct = (downloaded / total_bytes * 100) if total_bytes > 0 else 0
                    speed = (downloaded / (1024 * 1024)) / max(now - start_time, 0.01)
                    print(f"  -> {downloaded / (1024*1024):.1f} / {total_bytes / (1024*1024):.1f} MB ({pct:.1f}%) @ {speed:.2f} MB/s", end="\r", flush=True)
                    last_print = now

        print(f"\n  -> Finished {filename} in {time.time() - start_time:.1f}s")
        if tmp_file.exists():
            if dest_file.exists():
                dest_file.unlink()
            tmp_file.rename(dest_file)
        return True
    except Exception as e:
        print(f"\n[{idx}/{total}] ERROR downloading {filename}: {e}")
        if tmp_file.exists():
            tmp_file.unlink()
        return False

def main():
    dest_dir = Path(__file__).resolve().parent / "raw_cicids"
    dest_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("CIC-IDS2017 DATASET DOWNLOADER")
    print(f"Destination: {dest_dir}")
    print(f"Files to download: {len(FILES)} (~844 MB total)")
    print("=" * 70)

    success_count = 0
    start_all = time.time()
    for i, fname in enumerate(FILES, 1):
        if download_file(fname, dest_dir, i, len(FILES)):
            success_count += 1

    print("=" * 70)
    total_time = time.time() - start_all
    print(f"Download complete: {success_count}/{len(FILES)} files downloaded successfully in {total_time:.1f}s.")
    print("=" * 70)

    if success_count == len(FILES):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
