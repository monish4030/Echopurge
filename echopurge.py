#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ███████╗ ██████╗██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗██████╗ ║
║    ██╔════╝██╔════╝██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔══██╗║
║    █████╗  ██║     ███████║██║   ██║██████╔╝██║   ██║██║  ██║║
║    ██╔══╝  ██║     ██╔══██║██║   ██║██╔═══╝ ██║   ██║██║  ██║║
║    ███████╗╚██████╗██║  ██║╚██████╔╝██║     ╚██████╔╝██████╔╝║
║    ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═════╝ ║
║                                                               ║
║          Advanced Duplicate File Hunter & Purger              ║
║                  Made by Monish Paramasivam                   ║
╚═══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import hashlib
import argparse
import shutil
import json
import time
import stat
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
import threading

# ─────────────────────────────────────────────
#  ANSI Color & Style Helpers
# ─────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_DARK = "\033[40m"

def colored(text, *codes):
    return "".join(codes) + str(text) + C.RESET

def ok(msg):    print(colored(f"  ✔  {msg}", C.GREEN, C.BOLD))
def warn(msg):  print(colored(f"  ⚠  {msg}", C.YELLOW, C.BOLD))
def err(msg):   print(colored(f"  ✘  {msg}", C.RED, C.BOLD))
def info(msg):  print(colored(f"  ℹ  {msg}", C.CYAN))
def title(msg): print(colored(f"\n  {msg}", C.MAGENTA, C.BOLD))

# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ███████╗ ██████╗██╗  ██╗ ██████╗ ██████╗ ██╗   ██╗██████╗ ║
║    ██╔════╝██╔════╝██║  ██║██╔═══██╗██╔══██╗██║   ██║██╔══██╗║
║    █████╗  ██║     ███████║██║   ██║██████╔╝██║   ██║██║  ██║║
║    ██╔══╝  ██║     ██╔══██║██║   ██║██╔═══╝ ██║   ██║██║  ██║║
║    ███████╗╚██████╗██║  ██║╚██████╔╝██║     ╚██████╔╝██████╔╝║
║    ╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚═════╝ ║
║                                                               ║
║       {C.YELLOW}Advanced Duplicate File Hunter & Purger v1.0{C.CYAN}          ║
║             {C.DIM}Made by Monish Paramasivam{C.CYAN}                        ║
╚═══════════════════════════════════════════════════════════════╝
{C.RESET}"""

# ─────────────────────────────────────────────
#  Utilities
# ─────────────────────────────────────────────
def format_size(n_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n_bytes < 1024:
            return f"{n_bytes:.2f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.2f} PB"

def spinner(stop_event, message="Scanning"):
    frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]
    i = 0
    while not stop_event.is_set():
        frame = colored(frames[i % len(frames)], C.CYAN, C.BOLD)
        print(f"\r  {frame}  {colored(message, C.WHITE)}  ", end="", flush=True)
        time.sleep(0.08)
        i += 1
    print("\r" + " " * 60 + "\r", end="", flush=True)

# ─────────────────────────────────────────────
#  Core Hashing
# ─────────────────────────────────────────────
def quick_hash(filepath: str, block_size: int = 4096) -> Optional[str]:
    """Hash only the first + last block for a fast pre-check."""
    try:
        h = hashlib.md5()
        size = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            h.update(f.read(block_size))
            if size > block_size * 2:
                f.seek(-block_size, 2)
                h.update(f.read(block_size))
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

def full_hash(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """Full cryptographic hash of the entire file."""
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

# ─────────────────────────────────────────────
#  File Collection
# ─────────────────────────────────────────────
def collect_files(
    paths: list,
    min_size: int = 1,
    max_size: Optional[int] = None,
    extensions: Optional[list] = None,
    exclude_dirs: Optional[list] = None,
    follow_symlinks: bool = False
) -> list:
    """Walk directories and collect eligible files."""
    files = []
    seen_inodes = set()
    exclude_dirs = [os.path.abspath(d) for d in (exclude_dirs or [])]

    for base in paths:
        base = os.path.abspath(base)
        if not os.path.exists(base):
            warn(f"Path not found, skipping: {base}")
            continue

        if os.path.isfile(base):
            files.append(base)
            continue

        for root, dirs, filenames in os.walk(base, followlinks=follow_symlinks):
            # Prune excluded directories
            dirs[:] = [
                d for d in dirs
                if os.path.abspath(os.path.join(root, d)) not in exclude_dirs
                and not d.startswith(".")
            ]

            for fname in filenames:
                fpath = os.path.join(root, fname)

                # Extension filter
                if extensions:
                    if not any(fname.lower().endswith(e.lower()) for e in extensions):
                        continue

                try:
                    st = os.stat(fpath)
                except OSError:
                    continue

                # Skip symlinks unless requested
                if not follow_symlinks and stat.S_ISLNK(st.st_mode):
                    continue

                # Deduplicate via inode (hard-links)
                inode_key = (st.st_dev, st.st_ino)
                if inode_key in seen_inodes:
                    continue
                seen_inodes.add(inode_key)

                fsize = st.st_size
                if fsize < min_size:
                    continue
                if max_size is not None and fsize > max_size:
                    continue

                files.append(fpath)

    return files

# ─────────────────────────────────────────────
#  Duplicate Detection
# ─────────────────────────────────────────────
def find_duplicates(
    files: list,
    algorithm: str = "sha256",
    workers: int = 4,
    progress_cb=None
) -> dict:
    """
    Two-pass duplicate detection:
    Pass 1 — group by (size, quick_hash) to discard obvious non-duplicates fast.
    Pass 2 — full hash only the remaining candidates.
    Returns a dict of { full_hash: [list_of_paths] } for groups with > 1 file.
    """

    # ── Pass 1: group by size ──────────────────
    by_size = defaultdict(list)
    for fp in files:
        try:
            by_size[os.path.getsize(fp)].append(fp)
        except OSError:
            pass

    candidates = [fp for group in by_size.values() if len(group) > 1 for fp in group]

    if not candidates:
        return {}

    # ── Pass 2: quick hash ──────────────────────
    by_quick = defaultdict(list)
    for fp in candidates:
        qh = quick_hash(fp)
        if qh:
            by_quick[(os.path.getsize(fp), qh)].append(fp)

    final_candidates = [fp for group in by_quick.values() if len(group) > 1 for fp in group]

    if not final_candidates:
        return {}

    # ── Pass 3: full hash (parallel) ───────────
    full_hashes = {}
    lock = threading.Lock()
    done = [0]

    def hash_file(fp):
        h = full_hash(fp, algorithm)
        with lock:
            done[0] += 1
            if progress_cb:
                progress_cb(done[0], len(final_candidates))
        return fp, h

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(hash_file, fp): fp for fp in final_candidates}
        for future in as_completed(futures):
            fp, h = future.result()
            if h:
                full_hashes.setdefault(h, []).append(fp)

    return {h: paths for h, paths in full_hashes.items() if len(paths) > 1}

# ─────────────────────────────────────────────
#  Keep-Strategy
# ─────────────────────────────────────────────
def select_keeper(paths: list, strategy: str) -> str:
    """Return the path to KEEP based on strategy."""
    if strategy == "newest":
        return max(paths, key=lambda p: os.path.getmtime(p))
    elif strategy == "oldest":
        return min(paths, key=lambda p: os.path.getmtime(p))
    elif strategy == "shortest_path":
        return min(paths, key=lambda p: len(p))
    elif strategy == "longest_path":
        return max(paths, key=lambda p: len(p))
    else:  # default: newest
        return max(paths, key=lambda p: os.path.getmtime(p))

# ─────────────────────────────────────────────
#  Report Generation
# ─────────────────────────────────────────────
def generate_report(duplicates: dict, output_path: str):
    report = {
        "generated_at": datetime.now().isoformat(),
        "tool": "EchoPurge by Monish Paramasivam",
        "total_groups": len(duplicates),
        "total_duplicates": sum(len(v) - 1 for v in duplicates.values()),
        "wasted_bytes": sum(
            os.path.getsize(p) * (len(paths) - 1)
            for paths in duplicates.values()
            for p in [paths[0]]
        ),
        "groups": []
    }
    for h, paths in duplicates.items():
        size = os.path.getsize(paths[0])
        report["groups"].append({
            "hash": h,
            "file_size_bytes": size,
            "file_size_human": format_size(size),
            "copies": len(paths),
            "files": paths
        })
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    ok(f"Report saved → {output_path}")

# ─────────────────────────────────────────────
#  Interactive Review
# ─────────────────────────────────────────────
def interactive_review(duplicates: dict, strategy: str) -> list:
    """Let the user confirm each group before deletion."""
    to_delete = []
    groups = list(duplicates.items())
    total = len(groups)

    for idx, (h, paths) in enumerate(groups, 1):
        size = os.path.getsize(paths[0])
        keeper = select_keeper(paths, strategy)
        dupes  = [p for p in paths if p != keeper]

        print()
        print(colored(f"  ┌─ Group {idx}/{total} ─── {format_size(size)} each ─── {len(paths)} copies", C.BLUE, C.BOLD))
        for p in paths:
            tag = colored(" [KEEP]", C.GREEN, C.BOLD) if p == keeper else colored(" [DUPE]", C.RED)
            mtime = datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M")
            print(colored(f"  │  {tag}  {p}", C.WHITE) + colored(f"   ({mtime})", C.DIM))
        print(colored(f"  └{'─'*60}", C.BLUE))

        while True:
            answer = input(
                colored("  → Delete dupes? ", C.YELLOW, C.BOLD) +
                colored("[y]es / [n]o / [s]kip all remaining / [q]uit: ", C.DIM)
            ).strip().lower()
            if answer in ("y", "yes"):
                to_delete.extend(dupes)
                ok(f"Queued {len(dupes)} file(s) for deletion.")
                break
            elif answer in ("n", "no", ""):
                info("Skipped.")
                break
            elif answer in ("s", "skip"):
                info("Skipping all remaining groups.")
                return to_delete
            elif answer in ("q", "quit"):
                info("Quitting without further changes.")
                sys.exit(0)
            else:
                warn("Please enter y, n, s, or q.")

    return to_delete

# ─────────────────────────────────────────────
#  Deletion
# ─────────────────────────────────────────────
def delete_files(
    to_delete: list,
    dry_run: bool = False,
    trash_dir: Optional[str] = None
) -> tuple:
    deleted = []
    failed  = []

    for fp in to_delete:
        if dry_run:
            ok(f"[DRY-RUN] Would delete: {fp}")
            deleted.append(fp)
            continue
        try:
            if trash_dir:
                os.makedirs(trash_dir, exist_ok=True)
                dest = os.path.join(trash_dir, os.path.basename(fp))
                # Avoid collision in trash
                if os.path.exists(dest):
                    base, ext = os.path.splitext(dest)
                    dest = f"{base}_{int(time.time())}{ext}"
                shutil.move(fp, dest)
                ok(f"Trashed: {fp}")
            else:
                os.remove(fp)
                ok(f"Deleted: {fp}")
            deleted.append(fp)
        except (OSError, PermissionError) as e:
            err(f"Failed to remove {fp}: {e}")
            failed.append(fp)

    return deleted, failed

# ─────────────────────────────────────────────
#  Summary Table
# ─────────────────────────────────────────────
def print_summary(duplicates, deleted, failed, elapsed):
    total_groups  = len(duplicates)
    total_dupes   = sum(len(v) - 1 for v in duplicates.values())
    space_saved   = sum(
        os.path.getsize(p) if os.path.exists(p) else 0
        for p in deleted
    )
    # Estimate from hash groups
    wasted = 0
    for paths in duplicates.values():
        try:
            wasted += os.path.getsize(paths[0]) * (len(paths) - 1)
        except OSError:
            pass

    w = 56
    def row(label, value, color=C.WHITE):
        pad = w - len(label) - len(str(value)) - 4
        return (colored(f"  │  {label}", C.DIM) +
                " " * max(pad, 1) +
                colored(str(value), color) +
                colored("  │", C.DIM))

    sep = colored(f"  ├{'─' * (w)}┤", C.CYAN)
    top = colored(f"  ┌{'─' * (w)}┐", C.CYAN)
    bot = colored(f"  └{'─' * (w)}┘", C.CYAN)
    hdr = colored(f"  │{'  ECHOPURGE SUMMARY':^{w}}│", C.CYAN, C.BOLD)

    print(f"\n{top}\n{hdr}\n{sep}")
    print(row("Duplicate groups found",   total_groups,          C.YELLOW))
    print(row("Total duplicate files",    total_dupes,           C.YELLOW))
    print(row("Wasted space detected",    format_size(wasted),   C.YELLOW))
    print(sep)
    print(row("Files successfully removed", len(deleted),        C.GREEN))
    print(row("Files failed to remove",     len(failed),         C.RED if failed else C.DIM))
    print(row("Time elapsed",               f"{elapsed:.2f}s",   C.CYAN))
    print(bot)
    print(colored(f"\n  Made by Monish Paramasivam\n", C.DIM))

# ─────────────────────────────────────────────
#  Argument Parser
# ─────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="echopurge",
        description=colored("EchoPurge — Advanced Duplicate File Hunter & Purger", C.CYAN, C.BOLD),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=colored(
            "  Examples:\n"
            "    echopurge scan ~/Downloads\n"
            "    echopurge scan ~/Photos --ext .jpg .png --auto --strategy oldest\n"
            "    echopurge scan /data --min-size 1MB --dry-run --report report.json\n"
            "    echopurge scan . --trash ~/.echopurge_trash --workers 8\n\n"
            "  Made by Monish Paramasivam",
            C.DIM
        )
    )

    sub = p.add_subparsers(dest="command", metavar="<command>")

    # ── scan command ──────────────────────────
    scan = sub.add_parser("scan", help="Scan for and optionally delete duplicates")
    scan.add_argument("paths", nargs="+", metavar="PATH",
                      help="Directories or files to scan")

    scan.add_argument("--ext", nargs="*", metavar="EXT",
                      help="Filter by extensions, e.g. --ext .jpg .png .mp4")
    scan.add_argument("--min-size", default="1B", metavar="SIZE",
                      help="Minimum file size (e.g. 1B, 100KB, 5MB). Default: 1B")
    scan.add_argument("--max-size", default=None, metavar="SIZE",
                      help="Maximum file size (e.g. 500MB, 2GB)")
    scan.add_argument("--exclude", nargs="*", default=[], metavar="DIR",
                      help="Directories to exclude from scanning")
    scan.add_argument("--algorithm", default="sha256",
                      choices=["md5", "sha1", "sha256", "sha512"],
                      help="Hashing algorithm (default: sha256)")
    scan.add_argument("--workers", type=int, default=4, metavar="N",
                      help="Parallel worker threads (default: 4)")
    scan.add_argument("--strategy", default="newest",
                      choices=["newest", "oldest", "shortest_path", "longest_path"],
                      help="Which copy to KEEP (default: newest)")
    scan.add_argument("--auto", action="store_true",
                      help="Auto-delete duplicates without prompting")
    scan.add_argument("--dry-run", action="store_true",
                      help="Simulate deletions; no files are actually removed")
    scan.add_argument("--trash", metavar="DIR",
                      help="Move duplicates here instead of permanently deleting")
    scan.add_argument("--report", metavar="FILE",
                      help="Save a JSON report to this path")
    scan.add_argument("--follow-symlinks", action="store_true",
                      help="Follow symbolic links during scanning")
    scan.add_argument("--no-banner", action="store_true",
                      help="Suppress the ASCII banner")

    # ── version ───────────────────────────────
    p.add_argument("--version", action="version",
                   version="EchoPurge 1.0 — Made by Monish Paramasivam")

    return p

# ─────────────────────────────────────────────
#  Size Parsing
# ─────────────────────────────────────────────
def parse_size(s: str) -> int:
    s = s.strip().upper()
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
    for suffix, mult in sorted(units.items(), key=lambda x: -len(x[0])):
        if s.endswith(suffix):
            return int(float(s[:-len(suffix)]) * mult)
    try:
        return int(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid size: {s}")

# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────
def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        if not getattr(args, "no_banner", True):
            print(BANNER)
        parser.print_help()
        sys.exit(0)

    if not getattr(args, "no_banner", False):
        print(BANNER)

    start = time.time()

    # ── Parse sizes ───────────────────────────
    min_size = parse_size(args.min_size)
    max_size = parse_size(args.max_size) if args.max_size else None

    # ── Collect files ─────────────────────────
    title("Phase 1 — Collecting files…")
    stop = threading.Event()
    t = threading.Thread(target=spinner, args=(stop, "Walking directories"), daemon=True)
    t.start()

    files = collect_files(
        paths=args.paths,
        min_size=min_size,
        max_size=max_size,
        extensions=args.ext,
        exclude_dirs=args.exclude,
        follow_symlinks=args.follow_symlinks
    )
    stop.set(); t.join()

    if not files:
        warn("No eligible files found. Exiting.")
        sys.exit(0)

    ok(f"Found {colored(len(files), C.YELLOW, C.BOLD)} file(s) to analyse.")

    # ── Find duplicates ───────────────────────
    title("Phase 2 — Computing hashes…")
    progress_line = [""]
    lock = threading.Lock()

    def progress_cb(done, total):
        pct = done / total * 100
        bar = "█" * int(pct / 4) + "░" * (25 - int(pct / 4))
        line = f"\r  {colored(bar, C.CYAN)}  {colored(f'{pct:5.1f}%', C.WHITE)}  {done}/{total} files  "
        with lock:
            print(line, end="", flush=True)

    duplicates = find_duplicates(
        files=files,
        algorithm=args.algorithm,
        workers=args.workers,
        progress_cb=progress_cb
    )
    print()  # newline after progress

    if not duplicates:
        ok("No duplicates found! Your directory is already clean. ✨")
        elapsed = time.time() - start
        print_summary({}, [], [], elapsed)
        sys.exit(0)

    # ── Stats ─────────────────────────────────
    total_dupes = sum(len(v) - 1 for v in duplicates.values())
    wasted = sum(
        os.path.getsize(paths[0]) * (len(paths) - 1)
        for paths in duplicates.values()
    )
    print()
    warn(f"Found {colored(len(duplicates), C.RED, C.BOLD)} duplicate group(s)  ·  "
         f"{colored(total_dupes, C.RED, C.BOLD)} redundant files  ·  "
         f"{colored(format_size(wasted), C.RED, C.BOLD)} wasted")

    # ── Report ────────────────────────────────
    if args.report:
        title("Phase 3 — Generating report…")
        generate_report(duplicates, args.report)

    # ── Deletion phase ────────────────────────
    to_delete = []

    if args.auto:
        title("Phase 4 — Auto-selecting duplicates…")
        for paths in duplicates.values():
            keeper = select_keeper(paths, args.strategy)
            to_delete.extend(p for p in paths if p != keeper)
        info(f"Strategy '{args.strategy}': {len(to_delete)} file(s) queued for removal.")
    else:
        title("Phase 4 — Interactive review…")
        info(f"Strategy '{args.strategy}' will determine which copy is KEPT.")
        to_delete = interactive_review(duplicates, args.strategy)

    if not to_delete:
        info("Nothing selected for deletion. Goodbye!")
        elapsed = time.time() - start
        print_summary(duplicates, [], [], elapsed)
        sys.exit(0)

    # ── Confirm (unless dry-run or auto) ──────
    if not args.dry_run and not args.auto:
        print()
        confirm = input(
            colored(f"  ⚡ Permanently delete {len(to_delete)} file(s)?  ", C.RED, C.BOLD) +
            colored("Type 'YES' to confirm: ", C.YELLOW)
        ).strip()
        if confirm != "YES":
            info("Cancelled. No files were removed.")
            sys.exit(0)

    # ── Delete ────────────────────────────────
    title("Phase 5 — Removing duplicates…")
    if args.dry_run:
        warn("DRY-RUN mode — no files will actually be deleted.")
    deleted, failed = delete_files(
        to_delete,
        dry_run=args.dry_run,
        trash_dir=args.trash
    )

    elapsed = time.time() - start
    print_summary(duplicates, deleted, failed, elapsed)


if __name__ == "__main__":
    main()
