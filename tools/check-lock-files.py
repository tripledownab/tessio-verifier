#!/usr/bin/env python3
"""What belongs here: whether every committed packages.lock.json still records what NuGet resolves.

Run it after `dotnet restore Tessio.Verifier.sln --force-evaluate`, which rewrites each lock file from a
fresh resolution. This compares those files with the ones HEAD commits and fails on any difference in a
package NuGet resolved. It exits 1 when a lock file is stale and 2 when it cannot tell, so a caller can act
on staleness alone (.github/workflows/dependabot-lock-files.yml does).

WHY THE LOCKED RESTORE IS NOT ENOUGH. `dotnet restore --locked-mode` fails when a project's own package
references disagree with its lock file, but not when a TRANSITIVE package does. A package that arrives
through a ProjectReference can sit in a lock file at an old version and the locked restore passes. Put
AspNetCore's Cbor and Cose entries back to 10.0.12 after the bump to 10.0.13 and it still exits 0.
Comparing a fresh resolution with the committed files is the check that sees it.

WHY PROJECT ENTRIES ARE SKIPPED. A lock file also lists this repository's own projects, with the
version range each one requires of the others, and that range is this repository's version. Every
release bump moves it, and nothing is resolved from it, so comparing it would fail every release
without telling anyone about a package.
"""
import json
import subprocess
import sys
from pathlib import Path

LOCK_FILE = "packages.lock.json"
ROOT = Path(__file__).resolve().parent.parent
STALE, CANNOT_TELL = 1, 2


def cannot_tell(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(CANNOT_TELL)


def resolved(lock: dict) -> dict:
    """Every package entry by framework, without this repository's own projects."""
    return {
        tfm: {name: entry for name, entry in deps.items() if entry.get("type") != "Project"}
        for tfm, deps in lock.get("dependencies", {}).items()
    }


def git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def committed(path: Path) -> dict:
    """The lock file as HEAD commits it. A file HEAD does not carry is an error, not a skip: the restore
    writes one wherever a project asks for it, so an uncommitted lock file is one the commit forgot."""
    rel = path.relative_to(ROOT).as_posix()
    if git("cat-file", "-e", f"HEAD:{rel}").returncode != 0:
        cannot_tell(f"{rel} is not in HEAD. Commit it with the change that needs it.")
    shown = git("show", f"HEAD:{rel}")
    if shown.returncode != 0:
        cannot_tell(f"git could not read {rel} at HEAD: {shown.stderr.strip()}")
    return json.loads(shown.stdout)


def differences(before: dict, after: dict) -> list[str]:
    found = []
    for tfm in sorted(set(before) | set(after)):
        old, new = before.get(tfm), after.get(tfm)
        if old is None or new is None:
            found.append(f"{tfm}: {'added' if old is None else 'missing'}")
            continue
        for name in sorted(set(old) | set(new)):
            if old.get(name) != new.get(name):
                was = old.get(name, {}).get("resolved", "absent")
                now = new.get(name, {}).get("resolved", "absent")
                found.append(f"{tfm}: {name} {was} -> {now}")
    return found


def main() -> None:
    if git("rev-parse", "--verify", "HEAD").returncode != 0:
        cannot_tell(f"{ROOT} is not a git checkout with a HEAD to compare against.")
    paths = sorted(ROOT.glob(f"src/*/{LOCK_FILE}"))
    if not paths:
        cannot_tell(f"No src/*/{LOCK_FILE} under {ROOT}, so there is nothing to check. Restore first.")
    stale = []
    for path in paths:
        head = committed(path)
        for line in differences(resolved(head), resolved(json.loads(path.read_text()))):
            stale.append(f"{path.relative_to(ROOT)}: {line}")
    if stale:
        print("These lock files do not match what NuGet resolves now:", *stale, sep="\n  ")
        print("Run `dotnet restore Tessio.Verifier.sln --force-evaluate` and commit the lock files.")
        sys.exit(STALE)
    print("Every lock file matches what NuGet resolves.")


if __name__ == "__main__":
    main()
