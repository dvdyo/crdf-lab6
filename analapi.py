import os
import sys
import time
import hashlib
import datetime
import vt
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

def get_file_hash(filepath: Path):
    hasher = hashlib.sha256()
    try:
        content = filepath.read_bytes()
        hasher.update(content)
        return hasher.hexdigest()
    except IOError as e:
        print(f"[!] Error reading file {filepath}: {e}")
        return None

def print_report(report: dict, target_hash: str):
    stats = report.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())
    
    threat = report.get("popular_threat_classification", {}).get("suggested_threat_label", "N/A")
    name = report.get("meaningful_name", "N/A")
    ts = report.get("last_analysis_date")
    date_str = datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC') if ts else "N/A"

    print("-" * 60)
    print(f"Hash:      {target_hash}")
    print(f"Filename:  {name}")
    print(f"Verdict:   {malicious}/{total} malicious")
    print(f"Threat:    {threat}")
    print(f"Analyzed:  {date_str}")
    print(f"Link:      https://www.virustotal.com/gui/file/{target_hash}")
    print("-" * 60)

def check_hash(client: vt.Client, target_hash: str):
    try:
        print(f"[*] Checking: {target_hash} ...")
        report = client.get_object(
            f"/files/{target_hash}",
            params={"fields": "last_analysis_stats,meaningful_name,popular_threat_classification,last_analysis_date"}
        )
        print_report(report, target_hash)
    except vt.APIError as e:
        if e.code == "NotFoundError":
            print(f"[-] Hash not found in VirusTotal: {target_hash}")
        else:
            print(f"[!] API Error: {e}")

def process_target(client: vt.Client, target: str):
    path = Path(target)

    if path.is_file():
        if file_hash := get_file_hash(path):
            check_hash(client, file_hash)
    elif path.is_dir():
        files_to_scan = [p for p in path.rglob('*') if p.is_file()]
        for i, file_path in enumerate(files_to_scan):
            print(f"\n[{i+1}/{len(files_to_scan)}] Processing: {file_path.name}")
            if file_hash := get_file_hash(file_path):
                check_hash(client, file_hash)
            
            if i < len(files_to_scan) - 1:
                time.sleep(16)
    else:
        check_hash(client, target)

def main():
    if not API_KEY:
        print("[!] VT_API_KEY not found in .env file.")
        sys.exit(1)

    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <file_path|directory_path|hash>")
        sys.exit(1)

    client = vt.Client(API_KEY)
    try:
        target = sys.argv[1]
        process_target(client, target)
    finally:
        client.close()

if __name__ == "__main__":
    main()
