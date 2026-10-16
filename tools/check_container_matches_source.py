#!/usr/bin/env python3
"""
CHECK: is the RUNNING waf-api container built from the CURRENT source?

WHY THIS EXISTS. Three times on 2026-10-16 the running container was found to be
behind the working tree, and each time it was discovered by accident - once it was
two commits behind and had been silently writing rules to a path no vhost includes,
so every live deployment was inert while the code on disk looked correct.

    "we've been discussing a system that isn't the one running."

The failure mode is structural, not careless: `src/` is COPYed into the image at
build time, so ANY commit to src/ silently invalidates the running container, and
nothing anywhere says so. A rebuild is a manual step that is easy to forget and
impossible to notice.

WHAT IT DOES. Compares the container's src/*.py against the working tree, with line
endings normalised - because the container has LF and the Windows working copy has
CRLF, and a naive md5sum comparison reports a mismatch that is not real. That exact
mistake was made once already.

USAGE
    python tools/check_container_matches_source.py          # report, exit 0/1
    python tools/check_container_matches_source.py --files src/main.py

Exit 0 = the running system matches the source. Exit 1 = it does not (rebuild it),
exit 2 = could not tell (container not running, docker unavailable).

This is a REPORTING tool. It does not rebuild anything: rebuilding the running
system is a decision, not a side effect of a check.
"""
import argparse
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CONTAINER = os.getenv("WAF_CONTAINER", "waf-api")
CONTAINER_SRC = os.getenv("WAF_CONTAINER_SRC", "/app/src")

DEFAULT_FILES = ["src/main.py", "src/nginx_manager.py"]


def normalised_md5(data: bytes) -> str:
    """md5 of the bytes with CRLF folded to LF, so Windows-vs-Linux EOL is not a diff."""
    return hashlib.md5(data.replace(b"\r\n", b"\n")).hexdigest()


def host_digest(rel: str) -> str:
    return normalised_md5((REPO / rel).read_bytes())


def container_digest(rel: str) -> str:
    """Hash the file inside the container, normalising line endings there."""
    inner = os.path.basename(rel)
    script = (
        "import hashlib,sys;"
        f"d=open('{CONTAINER_SRC}/{inner}','rb').read();"
        "print(hashlib.md5(d.replace(b'\\r\\n',b'\\n')).hexdigest())"
    )
    proc = subprocess.run(
        ["docker", "exec", CONTAINER, "python", "-c", script],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"docker exec exited {proc.returncode}")
    return proc.stdout.strip()


def container_running() -> bool:
    proc = subprocess.run(
        ["docker", "ps", "--filter", f"name={CONTAINER}", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=30,
    )
    return proc.returncode == 0 and CONTAINER in proc.stdout


def image_created() -> str:
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{.Created}}", CONTAINER],
        capture_output=True, text=True, timeout=30,
    )
    return proc.stdout.strip()[:19] if proc.returncode == 0 else "unknown"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--files", nargs="*", default=DEFAULT_FILES,
                    help="repo-relative source files to compare")
    args = ap.parse_args()

    if not container_running():
        print(f"CANNOT TELL: container {CONTAINER!r} is not running.")
        return 2

    print(f"container {CONTAINER}  (image built {image_created()})")
    print(f"repo      {REPO}")
    print()

    mismatches = []
    for rel in args.files:
        try:
            h = host_digest(rel)
        except FileNotFoundError:
            print(f"  SKIP  {rel}: not in the working tree")
            continue
        try:
            c = container_digest(rel)
        except Exception as e:
            print(f"  ERROR {rel}: {e}")
            return 2
        same = (h == c)
        print(f"  {'OK  ' if same else 'STALE'} {rel}")
        print(f"          source    {h[:12]}")
        print(f"          container {c[:12]}")
        if not same:
            mismatches.append(rel)

    print()
    if mismatches:
        print("THE RUNNING SYSTEM IS NOT THE SOURCE YOU ARE READING.")
        print(f"  behind in: {', '.join(mismatches)}")
        print("  rebuild with:  docker compose build waf-api && "
              "docker compose up -d --no-deps waf-api")
        print()
        print("  Until then, anything you observe about behaviour describes the OLD code.")
        return 1

    print("The running system matches the source.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
