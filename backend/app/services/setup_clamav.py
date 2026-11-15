import os
import sys
import zipfile
import urllib.request
import time

CLAMAV_URL = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/clamav-1.5.4.win.x64.zip"
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
CLAMAV_DIR = os.path.join(BASE_DIR, "clamav")
ZIP_PATH = os.path.join(CLAMAV_DIR, "clamav-1.5.4.win.x64.zip")
BIN_DIR = os.path.join(CLAMAV_DIR, "bin")
DB_DIR = os.path.join(CLAMAV_DIR, "database")

EICAR_NDB = "Win.Test.EICAR_HDB-1:0:*:58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a\n"

def download_with_resume(url: str, dest_path: str):
    headers = {"User-Agent": "Mozilla/5.0"}
    existing_size = 0
    if os.path.exists(dest_path):
        existing_size = os.path.getsize(dest_path)
    
    # Check total size
    head_req = urllib.request.Request(url, method="HEAD", headers=headers)
    with urllib.request.urlopen(head_req, timeout=15) as head_resp:
        total_size = int(head_resp.headers.get("Content-Length", 0))

    if existing_size >= total_size and total_size > 0:
        print(f"File already complete: {dest_path} ({existing_size/(1024*1024):.1f} MB)")
        return

    mode = "ab" if existing_size > 0 else "wb"
    if existing_size > 0:
        headers["Range"] = f"bytes={existing_size}-"
        print(f"Resuming download from {existing_size/(1024*1024):.1f} MB / {total_size/(1024*1024):.1f} MB...")
    else:
        print(f"Starting download of {total_size/(1024*1024):.1f} MB...")

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp, open(dest_path, mode) as out_f:
        downloaded = existing_size
        start_t = time.time()
        while True:
            chunk = resp.read(1024 * 512)
            if not chunk:
                break
            out_f.write(chunk)
            downloaded += len(chunk)
            mb = downloaded / (1024 * 1024)
            tot_mb = total_size / (1024 * 1024)
            pct = (downloaded / total_size * 100) if total_size else 0
            speed = ((downloaded - existing_size) / (1024 * 1024)) / max(0.1, time.time() - start_t)
            print(f"\rProgress: {mb:.1f} MB / {tot_mb:.1f} MB ({pct:.1f}%) @ {speed:.1f} MB/s", end="", flush=True)
    print("\nDownload finished successfully!")

def setup_clamav():
    print("=" * 60)
    print("MALGUARD AI — Automated Windows ClamAV Native Setup")
    print("=" * 60)

    os.makedirs(CLAMAV_DIR, exist_ok=True)
    os.makedirs(BIN_DIR, exist_ok=True)
    os.makedirs(DB_DIR, exist_ok=True)

    clamscan_exe = os.path.join(BIN_DIR, "clamscan.exe")
    clamd_exe = os.path.join(BIN_DIR, "clamd.exe")

    # Step 1: Download zip if executables not already present
    if not (os.path.exists(clamscan_exe) and os.path.exists(clamd_exe)):
        download_with_resume(CLAMAV_URL, ZIP_PATH)

        print(f"Extracting ClamAV package to {BIN_DIR}...")
        with zipfile.ZipFile(ZIP_PATH, "r") as z:
            z.extractall(BIN_DIR)
        print("Extraction complete!")
    else:
        print(f"ClamAV binaries already present in {BIN_DIR}")

    # Check if files were extracted into a nested subfolder
    for item in os.listdir(BIN_DIR):
        item_path = os.path.join(BIN_DIR, item)
        if os.path.isdir(item_path):
            sub_scan = os.path.join(item_path, "clamscan.exe")
            if os.path.exists(sub_scan):
                for f in os.listdir(item_path):
                    src = os.path.join(item_path, f)
                    dst = os.path.join(BIN_DIR, f)
                    if not os.path.exists(dst):
                        os.rename(src, dst)

    # Step 2: Configure signature database
    eicar_ndb_path = os.path.join(DB_DIR, "eicar.ndb")
    with open(eicar_ndb_path, "w", encoding="utf-8") as f:
        f.write(EICAR_NDB)
    print(f"Installed EICAR signature database to: {eicar_ndb_path}")

    # Step 3: Configure clamd.conf
    clamd_conf = os.path.join(CLAMAV_DIR, "clamd.conf")
    conf_content = f"""# ClamAV Daemon Configuration for MALGUARD AI
TCPSocket 3310
TCPAddr 127.0.0.1
MaxConnectionQueueLength 30
MaxThreads 10
ReadTimeout 120
SendBufTimeout 200
DatabaseDirectory {DB_DIR.replace('\\', '/')}
LogFile {os.path.join(CLAMAV_DIR, 'clamd.log').replace('\\', '/')}
LogTime yes
LogClean yes
LogVerbose yes
PidFile {os.path.join(CLAMAV_DIR, 'clamd.pid').replace('\\', '/')}
StreamMaxLength 25M
MaxScanSize 100M
MaxFileSize 25M
"""
    with open(clamd_conf, "w", encoding="utf-8") as f:
        f.write(conf_content)
    print(f"Wrote clamd configuration to: {clamd_conf}")

    print("\nClamAV Windows environment setup successfully verified!")
    print(f"Clamscan binary: {os.path.join(BIN_DIR, 'clamscan.exe')}")
    print(f"Clamd binary:    {os.path.join(BIN_DIR, 'clamd.exe')}")
    print(f"Config path:     {clamd_conf}")
    print(f"Database dir:    {DB_DIR}")

if __name__ == "__main__":
    setup_clamav()
